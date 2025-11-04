/*
Copyright 2018 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Command server launches a stand-alone inverting proxy.
//
// Example usage:
//
//	go build -o ~/bin/inverting-proxy ./server/server.go
//	~/bin/inverting-proxy --port 8081
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/inverting-proxy/agent/utils"
	"github.com/gorilla/websocket"
)

var (
	port = flag.Int("port", 0, "Port on which to listen")
)

// pendingRequest represents a frontend request
type pendingRequest struct {
	startTime time.Time
	req       *http.Request
	respChan  chan *http.Response
}

func newPendingRequest(r *http.Request) *pendingRequest {
	return &pendingRequest{
		startTime: time.Now(),
		req:       r,
		respChan:  make(chan *http.Response),
	}
}

type bridgeConn struct {
	conn      net.Conn
	timestamp time.Time
}

type proxy struct {
	requestIDs    chan string
	randGenerator *rand.Rand

	// protects the map below
	sync.Mutex
	requests map[string]*pendingRequest
	// bridges maps request IDs to hijacked client connections for CONNECT tunneling.
	bridges map[string]*bridgeConn
}

func newProxy() *proxy {
	p := &proxy{
		requestIDs:    make(chan string),
		randGenerator: rand.New(rand.NewSource(time.Now().UnixNano())),
		requests:      make(map[string]*pendingRequest),
		bridges:       make(map[string]*bridgeConn),
	}
	// Start background goroutine to clean up stale bridges
	go p.cleanupStaleBridges()
	return p
}

// cleanupStaleBridges closes and removes hijacked client connections that have not been paired within timeout.
func (p *proxy) cleanupStaleBridges() {
	timeout := 60 * time.Second // configurable if needed
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		p.Lock()
		for id, bc := range p.bridges {
			if now.Sub(bc.timestamp) > timeout {
				log.Printf("Cleaning up stale bridge %s after %v", id, now.Sub(bc.timestamp))
				bc.conn.Close()
				delete(p.bridges, id)
			}
		}
		p.Unlock()
	}
}

func (p *proxy) handleAgentPostResponse(w http.ResponseWriter, r *http.Request, requestID string) {
	p.Lock()
	pending, ok := p.requests[requestID]
	p.Unlock()
	if !ok {
		log.Printf("Could not find pending request: %q", requestID)
		http.NotFound(w, r)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(r.Body), pending.req)
	if err != nil {
		log.Printf("Could not parse response to request %q: %v", requestID, err)
		http.Error(w, "Failure parsing request body", http.StatusBadRequest)
		return
	}
	// We want to track whether or not the body has finished being read so that we can
	// make sure that this method does not return until after that. However, we do not
	// want to block the sending of the response to the client while it is being read.
	//
	// To accommodate both goals, we replace the response body with a pipereader, start
	// forwarding the response immediately, and then copy the original body to the
	// corresponding pipewriter.
	respBody := resp.Body
	defer respBody.Close()

	pr, pw := io.Pipe()
	defer pw.Close()

	resp.Body = pr
	select {
	case <-r.Context().Done():
		return
	case pending.respChan <- resp:
	}
	if _, err := io.Copy(pw, respBody); err != nil {
		log.Printf("Could not read response to request %q: %v", requestID, err)
		http.Error(w, "Failure reading request body", http.StatusInternalServerError)
	}
}

func (p *proxy) handleAgentGetRequest(w http.ResponseWriter, r *http.Request, requestID string) {
	p.Lock()
	pending, ok := p.requests[requestID]
	p.Unlock()
	if !ok {
		log.Printf("Could not find pending request: %q", requestID)
		http.NotFound(w, r)
		return
	}
	log.Printf("Returning pending request: %q", requestID)
	w.Header().Set(utils.HeaderRequestStartTime, pending.startTime.Format(time.RFC3339Nano))
	w.WriteHeader(http.StatusOK)
	pending.req.Write(w)
}

// waitForRequestIDs blocks until at least one request ID is available, and then returns
// a slice of all of the IDs available at that time.
//
// Note that any IDs returned by this method will never be returned again.
func (p *proxy) waitForRequestIDs(ctx context.Context) []string {
	var requestIDs []string
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(30 * time.Second):
		return nil
	case id := <-p.requestIDs:
		requestIDs = append(requestIDs, id)
	}
	for {
		select {
		case id := <-p.requestIDs:
			requestIDs = append(requestIDs, id)
		default:
			return requestIDs
		}
	}
}

func (p *proxy) handleAgentListRequests(w http.ResponseWriter, r *http.Request) {
	requestIDs := p.waitForRequestIDs(r.Context())
	respJSON, err := json.Marshal(requestIDs)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failure serializing the request IDs: %v", err), http.StatusInternalServerError)
		return
	}
	log.Printf("Reporting pending requests: %s", respJSON)
	w.WriteHeader(http.StatusOK)
	w.Write(respJSON)
}

func (p *proxy) handleAgentRequest(w http.ResponseWriter, r *http.Request, backendID string) {
	requestID := r.Header.Get(utils.HeaderRequestID)
	if requestID == "" {
		log.Printf("Received new backend list request from %q", backendID)
		p.handleAgentListRequests(w, r)
		return
	}
	if r.Method == http.MethodPost {
		log.Printf("Received new backend post request from %q", backendID)
		p.handleAgentPostResponse(w, r, requestID)
		return
	}
	log.Printf("Received new backend get request from %q", backendID)
	p.handleAgentGetRequest(w, r, requestID)
}

func (p *proxy) newID() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d", p.randGenerator.Int63())))
	return fmt.Sprintf("%x", sum)
}

// isHopByHopHeader determines whether or not the given header name represents
// a header that is specific to a single network hop and thus should not be
// retransmitted by a proxy.
//
// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#hbh
func isHopByHopHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Handle bridge websocket connections from agents at /tcp-bridge/<id>
	if strings.HasPrefix(r.URL.Path, "/tcp-bridge/") {
		p.handleBridgeWebsocket(w, r)
		return
	}
	if backendID := r.Header.Get(utils.HeaderBackendID); backendID != "" {
		p.handleAgentRequest(w, r, backendID)
		return
	}
	// Support CONNECT by hijacking the client connection and waiting for the
	// agent to connect back via websocket to /tcp-bridge/<id> to form a tunnel.
	if r.Method == http.MethodConnect {
		id := p.newID()

		// Store a pending request so agents can fetch the CONNECT request.
		pending := newPendingRequest(r)
		p.Lock()
		p.requests[id] = pending
		p.Unlock()

		// Enqueue the request ID so agents learn about it.
		select {
		case <-r.Context().Done():
			return
		case p.requestIDs <- id:
		}

		// Hijack the client connection to perform raw TCP tunneling.
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hj.Hijack()
		if err != nil {
			http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
			return
		}
		// Write the 200 response to establish the tunnel.
		if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			clientConn.Close()
			return
		}

		// Save the client connection so that when the agent dials back to /tcp-bridge/<id>
		// we can pair the two ends.
		p.Lock()
		p.bridges[id] = &bridgeConn{conn: clientConn, timestamp: time.Now()}
		p.Unlock()
		// Return from handler; the connection will be closed by the bridge handler when paired.
		return
	}
	id := p.newID()
	log.Printf("Received new frontend request %q", id)
	// Filter out hop-by-hop headers from the request
	for name := range r.Header {
		if isHopByHopHeader(name) {
			r.Header.Del(name)
		}
	}
	pending := newPendingRequest(r)
	p.Lock()
	p.requests[id] = pending
	p.Unlock()

	// Enqueue the request
	select {
	case <-r.Context().Done():
		// The client request was cancelled
		log.Printf("Timeout waiting to enqueue the request ID for %q", id)
		return
	case p.requestIDs <- id:
	}
	log.Printf("Request %q enqueued after %s", id, time.Since(pending.startTime))
	// Pull out and copy the response
	defer log.Printf("Response for %q received after %s", id, time.Since(pending.startTime))
	select {
	case <-r.Context().Done():
		// The client request was cancelled
		log.Printf("Timeout waiting for the response to %q", id)
		return
	case resp := <-pending.respChan:
		// Copy all of the non-hop-by-hop headers to the proxied response
		for name, vals := range resp.Header {
			if isHopByHopHeader(name) {
				continue
			}
			w.Header()[name] = vals
		}
		w.Header().Add("transfer-encoding", "chunked")
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		resp.Body.Close()
		for name, vals := range resp.Trailer {
			if isHopByHopHeader(name) {
				continue
			}
			for _, v := range vals {
				w.Header().Add(http.TrailerPrefix+name, v)
			}
		}
		return
	}
}

// handleBridgeWebsocket upgrades an incoming websocket from an agent intended to
// bridge a TCP connection, pairs it with the previously-hijacked client
// connection stored in p.bridges, and proxies bytes both ways.
func (p *proxy) handleBridgeWebsocket(w http.ResponseWriter, r *http.Request) {
	// path is /tcp-bridge/<id>
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 || parts[2] == "" {
		http.Error(w, "Missing bridge id", http.StatusBadRequest)
		return
	}
	id := parts[2]

	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}
	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade websocket for bridge %s: %v", id, err)
		return
	}

	p.Lock()
	bc, ok := p.bridges[id]
	if ok {
		delete(p.bridges, id)
	}
	p.Unlock()

	if !ok {
		// No client waiting for this bridge; close websocket.
		log.Printf("No client connection waiting for bridge %s", id)
		wsConn.Close()
		return
	}
	clientConn := bc.conn

	// Wrap websocket as net.Conn using gorilla websocket's NextReader/NextWriter
	// Implement a simple adapter that reads text/binary messages as raw bytes.
	done := make(chan struct{})
	go func() {
		defer wsConn.Close()
		defer clientConn.Close()
		// copy from websocket to clientConn
		for {
			_, msg, err := wsConn.ReadMessage()
			if err != nil {
				break
			}
			if _, err := clientConn.Write(msg); err != nil {
				break
			}
		}
		close(done)
	}()
	// copy from clientConn to websocket
	buf := make([]byte, 32*1024)
	for {
		n, err := clientConn.Read(buf)
		if n > 0 {
			if err := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	<-done
}

func main() {
	flag.Parse()
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to create the TCP listener for port %d: %v", *port, err)
	}
	log.Printf("Listening on %s", listener.Addr())
	log.Fatal(http.Serve(listener, newProxy()))
}
