package httpmask

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type handleConnResult struct {
	result HandleResult
	conn   net.Conn
	err    error
}

// doTunnelRequest runs one HTTP request through server.HandleConn and returns
// the response (with its body read) and what HandleConn returned.
func doTunnelRequest(t *testing.T, server *TunnelServer, method, target string) (*http.Response, string, handleConnResult) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan handleConnResult, 1)
	go func() {
		result, conn, err := server.HandleConn(serverConn)
		done <- handleConnResult{result, conn, err}
	}()

	request := method + " " + target + " HTTP/1.1\r\nHost: example.com\r\nX-Sudoku-Tunnel: stream\r\nContent-Length: 0\r\n\r\n"
	if _, err := io.WriteString(clientConn, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientConn), &http.Request{Method: method})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = clientConn.Close()
	return resp, string(body), <-done
}

func openTestSession(t *testing.T, server *TunnelServer) (string, net.Conn) {
	t.Helper()
	resp, body, res := doTunnelRequest(t, server, http.MethodGet, "/session")
	if resp.StatusCode != http.StatusOK || res.result != HandleStartTunnel {
		t.Fatalf("open session: status %d, result %v", resp.StatusCode, res.result)
	}
	for _, line := range strings.Split(body, "\n") {
		if token, ok := strings.CutPrefix(line, "token="); ok {
			return token, res.conn
		}
	}
	t.Fatalf("no token in %q", body)
	return "", nil
}

func setPendingLimits(t *testing.T, limit int, timeout time.Duration) {
	oldLimit, oldTimeout := maxPendingTunnelSessions, pendingTunnelSessionTimeout
	maxPendingTunnelSessions, pendingTunnelSessionTimeout = limit, timeout
	t.Cleanup(func() {
		maxPendingTunnelSessions, pendingTunnelSessionTimeout = oldLimit, oldTimeout
	})
}

// answer makes the inner protocol write downlink bytes and pulls them, as a
// client does after its handshake.
func answer(t *testing.T, server *TunnelServer, token string, tunnel net.Conn) {
	t.Helper()
	go func() { _, _ = tunnel.Write([]byte("server hello")) }()
	resp, body, _ := doTunnelRequest(t, server, http.MethodGet, "/stream?token="+token)
	if resp.StatusCode != http.StatusOK || body != "server hello" {
		t.Fatalf("pull: status %d, body %q", resp.StatusCode, body)
	}
}

func TestTunnelServerCapsPendingSessions(t *testing.T) {
	setPendingLimits(t, 2, time.Minute)
	server := NewTunnelServer(TunnelServerOptions{Mode: "stream", PullReadTimeout: 50 * time.Millisecond})

	token1, tunnel1 := openTestSession(t, server)
	defer tunnel1.Close()
	_, tunnel2 := openTestSession(t, server)
	defer tunnel2.Close()

	resp, _, res := doTunnelRequest(t, server, http.MethodGet, "/session")
	if resp.StatusCode != http.StatusServiceUnavailable || res.result != HandleDone {
		t.Fatalf("third pending session: status %d, result %v, want 503", resp.StatusCode, res.result)
	}

	// once the inner protocol has answered, the session no longer counts
	answer(t, server, token1, tunnel1)
	token3, tunnel3 := openTestSession(t, server)
	defer tunnel3.Close()
	if !server.sessionHas(token3) {
		t.Fatal("session not registered after a pending slot was freed")
	}
}

func TestTunnelServerClosesPendingSessionAfterTimeout(t *testing.T) {
	setPendingLimits(t, 16, 100*time.Millisecond)
	server := NewTunnelServer(TunnelServerOptions{Mode: "stream", PullReadTimeout: 50 * time.Millisecond})

	pendingToken, pendingTunnel := openTestSession(t, server)
	defer pendingTunnel.Close()
	answeredToken, answeredTunnel := openTestSession(t, server)
	defer answeredTunnel.Close()
	answer(t, server, answeredToken, answeredTunnel)

	deadline := time.Now().Add(2 * time.Second)
	for server.sessionHas(pendingToken) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if server.sessionHas(pendingToken) {
		t.Fatal("pending session survived its deadline")
	}
	// the pipe of a reaped session is closed for the inner protocol too
	_ = pendingTunnel.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := pendingTunnel.Read(make([]byte, 1)); err == nil {
		t.Fatal("read on a reaped session succeeded")
	}

	time.Sleep(200 * time.Millisecond)
	if !server.sessionHas(answeredToken) {
		t.Fatal("answered session reaped by the pending deadline")
	}
	server.mu.Lock()
	pending := server.pending
	server.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending count = %d, want 0", pending)
	}
}
