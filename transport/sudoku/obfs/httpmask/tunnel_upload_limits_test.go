package httpmask

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func setUploadLimits(t *testing.T, limit int, timeout time.Duration) {
	t.Helper()
	oldLimit, oldTimeout := maxConcurrentSessionUploads, uploadBodyReadTimeout
	maxConcurrentSessionUploads, uploadBodyReadTimeout = limit, timeout
	t.Cleanup(func() {
		maxConcurrentSessionUploads, uploadBodyReadTimeout = oldLimit, oldTimeout
	})
}

type stalledUpload struct {
	client net.Conn
	done   chan handleConnResult
	status chan int // response status, or 0 if the socket closed without one
}

// startStalledUpload sends the header of an upload that announces a body and
// never sends it.
func startStalledUpload(t *testing.T, server *TunnelServer, mode, token string) *stalledUpload {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	u := &stalledUpload{
		client: clientConn,
		done:   make(chan handleConnResult, 1),
		status: make(chan int, 1),
	}
	finished := make(chan struct{})
	// The handler reads the limits that setUploadLimits restores, so it must
	// be gone before that cleanup runs (cleanups run last-in, first-out).
	t.Cleanup(func() {
		_ = clientConn.Close()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("upload handler did not exit")
		}
	})
	go func() {
		defer close(finished)
		result, conn, err := server.HandleConn(serverConn)
		u.done <- handleConnResult{result, conn, err}
	}()
	request := "POST /api/v1/upload?token=" + token + "&seq=1 HTTP/1.1\r\nHost: example.com\r\nX-Sudoku-Tunnel: " + mode + "\r\nContent-Length: 4096\r\n\r\n"
	if _, err := io.WriteString(clientConn, request); err != nil {
		t.Fatalf("write upload header: %v", err)
	}
	go func() {
		resp, err := http.ReadResponse(bufio.NewReader(clientConn), &http.Request{Method: http.MethodPost})
		if err != nil {
			u.status <- 0
			return
		}
		_ = resp.Body.Close()
		u.status <- resp.StatusCode
	}()
	return u
}

func (u *stalledUpload) waitDone(t *testing.T, within time.Duration, what string) {
	t.Helper()
	select {
	case <-u.done:
	case <-time.After(within):
		t.Fatalf("%s: upload handler still blocked after %v", what, within)
	}
}

func TestTunnelServerUploadBodyHasDeadline(t *testing.T) {
	setUploadLimits(t, 8, 100*time.Millisecond)
	for _, mode := range []string{"stream", "poll"} {
		t.Run(mode, func(t *testing.T) {
			server := NewTunnelServer(TunnelServerOptions{Mode: "auto", PullReadTimeout: 50 * time.Millisecond})
			token, tunnel := openTestSession(t, server)
			defer tunnel.Close()

			u := startStalledUpload(t, server, mode, token)
			u.waitDone(t, 2*time.Second, "stalled body")
		})
	}
}

func TestTunnelServerCapsConcurrentUploadsPerSession(t *testing.T) {
	setUploadLimits(t, 2, time.Minute)
	for _, mode := range []string{"stream", "poll"} {
		t.Run(mode, func(t *testing.T) {
			server := NewTunnelServer(TunnelServerOptions{Mode: "auto", PullReadTimeout: 50 * time.Millisecond})
			token, tunnel := openTestSession(t, server)
			defer tunnel.Close()

			startStalledUpload(t, server, mode, token)
			startStalledUpload(t, server, mode, token)
			waitUploads(t, server, token, 2)

			third := startStalledUpload(t, server, mode, token)
			third.waitDone(t, 2*time.Second, "upload over the cap")
			if status := <-third.status; status != http.StatusServiceUnavailable {
				t.Fatalf("upload over the cap: status %d, want 503", status)
			}
		})
	}
}

func TestTunnelServerSessionCloseEndsUploads(t *testing.T) {
	setUploadLimits(t, 8, time.Minute)
	for _, mode := range []string{"stream", "poll"} {
		t.Run(mode, func(t *testing.T) {
			server := NewTunnelServer(TunnelServerOptions{Mode: "auto", PullReadTimeout: 50 * time.Millisecond})
			token, tunnel := openTestSession(t, server)
			defer tunnel.Close()

			u := startStalledUpload(t, server, mode, token)
			waitUploads(t, server, token, 1)
			server.sessionClose(token)
			u.waitDone(t, 2*time.Second, "closed session")
		})
	}
}

func TestTunnelServerPendingReapEndsUploads(t *testing.T) {
	setPendingLimits(t, 16, 100*time.Millisecond)
	setUploadLimits(t, 8, time.Minute)
	server := NewTunnelServer(TunnelServerOptions{Mode: "stream", PullReadTimeout: 50 * time.Millisecond})
	token, tunnel := openTestSession(t, server)
	defer tunnel.Close()

	u := startStalledUpload(t, server, "stream", token)
	u.waitDone(t, 2*time.Second, "reaped pending session")
}

func waitUploads(t *testing.T, server *TunnelServer, token string, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		server.mu.Lock()
		n := 0
		if sess := server.sessions[token]; sess != nil {
			n = len(sess.uploads)
		}
		server.mu.Unlock()
		if n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("session has %d uploads, want %d", n, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
