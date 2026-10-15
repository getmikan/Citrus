package trusttunnel

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/tls"
)

func startHandshakeTimeoutServer(t *testing.T, timeout time.Duration) string {
	t.Helper()
	old := handshakeTimeout
	handshakeTimeout = timeout
	t.Cleanup(func() { handshakeTimeout = old })
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(backend.Close)
	_, addr := startFallbackServer(t, backend, time.Minute)
	return addr
}

func expectClosedWithin(t *testing.T, conn net.Conn, limit time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(limit))
	_, err := conn.Read(make([]byte, 1))
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("server kept the unauthenticated conn open for %v", limit)
	}
	if err == nil {
		t.Fatal("server sent data to a silent client")
	}
}

func TestHandshakeTimeoutSilentTCPClient(t *testing.T) {
	addr := startHandshakeTimeoutServer(t, 200*time.Millisecond)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// no ClientHello at all
	expectClosedWithin(t, conn, 5*time.Second)
}

func TestHandshakeTimeoutSilentHTTP1Client(t *testing.T) {
	addr := startHandshakeTimeoutServer(t, 200*time.Millisecond)
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// TLS done, no request header
	expectClosedWithin(t, conn, 5*time.Second)
}
