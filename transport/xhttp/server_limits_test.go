package xhttp

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setPendingSessionLimits(t *testing.T, max int, timeout time.Duration) {
	oldMax, oldTimeout := maxPendingSessions, pendingSessionTimeout
	maxPendingSessions, pendingSessionTimeout = max, timeout
	t.Cleanup(func() { maxPendingSessions, pendingSessionTimeout = oldMax, oldTimeout })
}

func packetUpload(t *testing.T, handler http.Handler, session, seq string, payload []byte) int {
	t.Helper()
	config := Config{Path: "/xhttp", Mode: "packet-up"}
	req := httptest.NewRequest(http.MethodPost, "https://example.com/xhttp", nil)
	require.NoError(t, config.FillPacketRequest(req, session, seq, payload))
	if req.Body == nil {
		req.Body = http.NoBody
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder.Result().StatusCode
}

func sessionDownload(t *testing.T, handler http.Handler, session string) int {
	t.Helper()
	config := Config{Path: "/xhttp", Mode: "packet-up"}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/xhttp", http.NoBody)
	require.NoError(t, config.FillStreamRequest(req, session))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder.Result().StatusCode
}

func pendingCount(h *requestHandler) (pending, total int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pending, len(h.sessions)
}

func TestServerHandlerPendingSessionCap(t *testing.T) {
	setPendingSessionLimits(t, 2, time.Minute)
	read := make(chan struct{})
	handler, err := NewServerHandler(ServerOption{
		Config: Config{Path: "/xhttp", Mode: "packet-up"},
		ConnHandler: func(conn net.Conn, _ *http.Request) {
			_, _ = io.ReadFull(conn, make([]byte, 4))
			close(read)
			_, _ = io.Copy(io.Discard, conn)
		},
	})
	require.NoError(t, err)
	h := handler.(*requestHandler)

	assert.Equal(t, http.StatusOK, packetUpload(t, handler, "a", "0", []byte("data")))
	assert.Equal(t, http.StatusOK, packetUpload(t, handler, "b", "0", []byte("data")))
	assert.Equal(t, http.StatusServiceUnavailable, packetUpload(t, handler, "c", "0", []byte("data")))
	assert.Equal(t, http.StatusServiceUnavailable, sessionDownload(t, handler, "c"))
	// Existing sessions keep working while the cap is reached.
	assert.Equal(t, http.StatusOK, packetUpload(t, handler, "a", "1", []byte("more")))

	// Once a session delivers data it no longer counts towards the cap.
	done := make(chan int)
	go func() { done <- sessionDownload(t, handler, "a") }()
	<-read
	assert.Eventually(t, func() bool { p, _ := pendingCount(h); return p == 1 }, time.Second, 5*time.Millisecond)
	assert.Equal(t, http.StatusOK, packetUpload(t, handler, "c", "0", []byte("data")))
	p, total := pendingCount(h)
	assert.Equal(t, 2, p)
	assert.Equal(t, 3, total)

	h.deleteSession("a", h.getSession("a"))
	assert.Equal(t, http.StatusOK, <-done)
	p, total = pendingCount(h)
	assert.Equal(t, 2, p)
	assert.Equal(t, 2, total)
}

// A download whose upload never brings any data is closed after the deadline.
func TestServerHandlerPendingSessionTimeout(t *testing.T) {
	setPendingSessionLimits(t, 16, 100*time.Millisecond)
	readErr := make(chan error, 1)
	handler, err := NewServerHandler(ServerOption{
		Config: Config{Path: "/xhttp", Mode: "packet-up"},
		ConnHandler: func(conn net.Conn, _ *http.Request) {
			_, err := conn.Read(make([]byte, 1))
			readErr <- err
			_ = conn.Close()
		},
	})
	require.NoError(t, err)
	h := handler.(*requestHandler)

	done := make(chan int)
	go func() { done <- sessionDownload(t, handler, "idle") }()
	select {
	case status := <-done:
		assert.Equal(t, http.StatusOK, status)
	case <-time.After(5 * time.Second):
		t.Fatal("idle download was not closed")
	}
	assert.Error(t, <-readErr)
	p, total := pendingCount(h)
	assert.Equal(t, 0, p)
	assert.Equal(t, 0, total)

	// An upload-only session (the download never comes) is reaped too.
	assert.Equal(t, http.StatusOK, packetUpload(t, handler, "orphan", "0", []byte("data")))
	assert.Eventually(t, func() bool { _, n := pendingCount(h); return n == 0 }, 5*time.Second, 10*time.Millisecond)
}

// Once data flows, the session outlives the deadline.
func TestServerHandlerActiveSessionNotReaped(t *testing.T) {
	setPendingSessionLimits(t, 16, 100*time.Millisecond)
	got := make(chan []byte, 1)
	handler, err := NewServerHandler(ServerOption{
		Config: Config{Path: "/xhttp", Mode: "packet-up"},
		ConnHandler: func(conn net.Conn, _ *http.Request) {
			b := make([]byte, 4)
			_, _ = io.ReadFull(conn, b)
			b2, _ := io.ReadAll(conn)
			got <- append(b, b2...)
			_ = conn.Close()
		},
	})
	require.NoError(t, err)
	h := handler.(*requestHandler)

	assert.Equal(t, http.StatusOK, packetUpload(t, handler, "live", "0", []byte("head")))
	done := make(chan int)
	go func() { done <- sessionDownload(t, handler, "live") }()

	time.Sleep(400 * time.Millisecond)
	p, total := pendingCount(h)
	assert.Equal(t, 0, p)
	assert.Equal(t, 1, total)
	assert.Equal(t, http.StatusOK, packetUpload(t, handler, "live", "1", []byte("tail")))

	h.getSession("live").uploadQueue.Close()
	assert.Equal(t, http.StatusOK, <-done)
	assert.True(t, bytes.Equal([]byte("headtail"), <-got))
	_, total = pendingCount(h)
	assert.Equal(t, 0, total)
}

// Closing an old session must not remove a newer one registered under the same ID.
func TestServerHandlerDeleteSessionKeepsNewer(t *testing.T) {
	handler, err := NewServerHandler(ServerOption{Config: Config{Path: "/xhttp", Mode: "packet-up"}})
	require.NoError(t, err)
	h := handler.(*requestHandler)
	old := h.upsertSession("id")
	h.deleteSession("id", old)
	newer := h.upsertSession("id")
	h.deleteSession("id", old)
	assert.Same(t, newer, h.getSession("id"))
	h.deleteSession("id", newer)
	p, total := pendingCount(h)
	assert.Equal(t, 0, p)
	assert.Equal(t, 0, total)
}
