package xhttp

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func packetUpHandler(t *testing.T, opt ServerOption) *requestHandler {
	t.Helper()
	if opt.Config.Path == "" {
		opt.Config = Config{Path: "/xhttp", Mode: "packet-up"}
	}
	handler, err := NewServerHandler(opt)
	require.NoError(t, err)
	return handler.(*requestHandler)
}

// A session ID is attacker input kept as a map key before anything is
// authenticated; an oversized one is refused before a session is created.
func TestServerHandlerRejectsOversizedSessionID(t *testing.T) {
	h := packetUpHandler(t, ServerOption{})
	long := strings.Repeat("a", maxSessionIDLength+1)
	assert.Equal(t, http.StatusBadRequest, packetUpload(t, h, long, "0", []byte("data")))
	assert.Equal(t, http.StatusBadRequest, sessionDownload(t, h, long))
	_, total := pendingCount(h)
	assert.Equal(t, 0, total)

	ok := strings.Repeat("a", maxSessionIDLength)
	assert.Equal(t, http.StatusOK, packetUpload(t, h, ok, "0", []byte("data")))
	h.deleteSession(ok, h.getSession(ok))
}

// With ReportsAuthentication the session stays pending (capped and reaped)
// after its first upload bytes reach the inner handler, until the handler
// reports the client authenticated: one byte no longer frees a pending slot.
func TestServerHandlerPendingUntilAuthenticated(t *testing.T) {
	setPendingSessionLimits(t, 2, time.Minute)
	authenticate := make(chan func(), 2)
	readOne := make(chan struct{}, 2)
	h := packetUpHandler(t, ServerOption{
		ReportsAuthentication: true,
		ConnHandler: func(conn net.Conn, r *http.Request) {
			_, _ = io.ReadFull(conn, make([]byte, 1))
			readOne <- struct{}{}
			authenticate <- OnAuthenticated(r)
			_, _ = io.Copy(io.Discard, conn)
		},
	})

	var downloads sync.WaitGroup
	for _, id := range []string{"a", "b"} {
		assert.Equal(t, http.StatusOK, packetUpload(t, h, id, "0", []byte{0}))
		downloads.Add(1)
		go func() { defer downloads.Done(); sessionDownload(t, h, id) }()
		<-readOne
	}
	// both sessions delivered a byte, neither is authenticated
	p, _ := pendingCount(h)
	assert.Equal(t, 2, p)
	assert.Equal(t, http.StatusServiceUnavailable, packetUpload(t, h, "c", "0", []byte{0}))

	auth := <-authenticate
	require.NotNil(t, auth)
	auth()
	p, _ = pendingCount(h)
	assert.Equal(t, 1, p)
	assert.Equal(t, http.StatusOK, packetUpload(t, h, "c", "0", []byte{0}))

	for _, id := range []string{"a", "b", "c"} {
		if s := h.getSession(id); s != nil {
			h.deleteSession(id, s)
		}
	}
	downloads.Wait()
	p, total := pendingCount(h)
	assert.Equal(t, 0, p)
	assert.Equal(t, 0, total)
}

// A session that never authenticates is reaped even though data flowed.
func TestServerHandlerUnauthenticatedSessionReaped(t *testing.T) {
	setPendingSessionLimits(t, 16, 100*time.Millisecond)
	h := packetUpHandler(t, ServerOption{
		ReportsAuthentication: true,
		ConnHandler: func(conn net.Conn, _ *http.Request) {
			_, _ = io.Copy(io.Discard, conn)
			_ = conn.Close()
		},
	})
	assert.Equal(t, http.StatusOK, packetUpload(t, h, "s", "0", []byte("data")))
	done := make(chan int)
	go func() { done <- sessionDownload(t, h, "s") }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("unauthenticated session was not reaped")
	}
	_, total := pendingCount(h)
	assert.Equal(t, 0, total)
}

// stalledUpload starts a packet-up upload whose body never completes.
func stalledUpload(t *testing.T, h http.Handler, session, seq string) (status chan int, stop func()) {
	t.Helper()
	config := Config{Path: "/xhttp", Mode: "packet-up"}
	req := httptest.NewRequest(http.MethodPost, "https://example.com/xhttp", nil)
	require.NoError(t, config.FillPacketRequest(req, session, seq, nil))
	pr, pw := io.Pipe()
	req.Body, req.ContentLength = pr, 100
	status = make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		status <- rec.Result().StatusCode
	}()
	return status, func() { _ = pw.CloseWithError(io.ErrUnexpectedEOF) }
}

// A pending session admits only as many uploads at a time as its queue holds
// packets; more used to each hold a request and a body reader without limit.
func TestServerHandlerPendingUploadsCapped(t *testing.T) {
	h := packetUpHandler(t, ServerOption{
		Config: Config{Path: "/xhttp", Mode: "packet-up", ScMaxBufferedPosts: "2"},
	})
	s1, stop1 := stalledUpload(t, h, "s", "0")
	defer stop1()
	s2, stop2 := stalledUpload(t, h, "s", "1")
	defer stop2()
	assert.Eventually(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		s := h.sessions["s"]
		return s != nil && s.uploads == 2
	}, 5*time.Second, 5*time.Millisecond)

	s3, stop3 := stalledUpload(t, h, "s", "2")
	defer stop3()
	select {
	case code := <-s3:
		assert.Equal(t, http.StatusServiceUnavailable, code)
	case <-time.After(5 * time.Second):
		t.Fatal("third concurrent pending upload was admitted")
	}
	stop1()
	stop2()
	assert.Equal(t, http.StatusBadRequest, <-s1)
	assert.Equal(t, http.StatusBadRequest, <-s2)
	h.deleteSession("s", h.getSession("s"))
}

// The body of an upload to a pending session must arrive in time.
func TestServerHandlerPendingUploadBodyDeadline(t *testing.T) {
	old := pendingUploadTimeout
	pendingUploadTimeout = 200 * time.Millisecond
	t.Cleanup(func() { pendingUploadTimeout = old })
	h := packetUpHandler(t, ServerOption{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	config := Config{Path: "/xhttp", Mode: "packet-up"}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/xhttp", nil)
	require.NoError(t, err)
	require.NoError(t, config.FillPacketRequest(req, "s", "0", nil))
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() { _, _ = pw.Write([]byte("x")) }() // then nothing
	req.Body, req.ContentLength, req.GetBody = pr, 100, nil
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err, "a trickled pending upload was not cut")
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	srv.Close()
	assert.Eventually(t, func() bool { _, n := pendingCount(h); return n <= 1 }, time.Second, 10*time.Millisecond)
}

// Upload payload accepted by pending sessions is bounded in total.
func TestServerHandlerPendingUploadBytesBudget(t *testing.T) {
	old := maxPendingUploadBytes
	maxPendingUploadBytes = 10
	t.Cleanup(func() { maxPendingUploadBytes = old })
	h := packetUpHandler(t, ServerOption{})

	assert.Equal(t, http.StatusOK, packetUpload(t, h, "a", "0", []byte("123456")))
	assert.Equal(t, http.StatusServiceUnavailable, packetUpload(t, h, "b", "0", []byte("123456")))
	assert.Equal(t, http.StatusOK, packetUpload(t, h, "b", "0", []byte("1234")))
	// removing a session returns its share
	h.deleteSession("a", h.getSession("a"))
	assert.Equal(t, http.StatusOK, packetUpload(t, h, "c", "0", []byte("123456")))
	h.mu.Lock()
	assert.Equal(t, 10, h.pendingBytes)
	h.mu.Unlock()
	h.deleteSession("b", h.getSession("b"))
	h.deleteSession("c", h.getSession("c"))
	h.mu.Lock()
	assert.Equal(t, 0, h.pendingBytes)
	h.mu.Unlock()
}

// One session has one download: a second one would run a second inner
// handler on the same upload queue.
func TestServerHandlerSecondDownloadRefused(t *testing.T) {
	started := make(chan struct{}, 2)
	h := packetUpHandler(t, ServerOption{
		ConnHandler: func(conn net.Conn, _ *http.Request) {
			started <- struct{}{}
			_, _ = io.Copy(io.Discard, conn)
		},
	})
	done := make(chan int)
	go func() { done <- sessionDownload(t, h, "s") }()
	<-started
	assert.Equal(t, http.StatusConflict, sessionDownload(t, h, "s"))
	h.deleteSession("s", h.getSession("s"))
	assert.Equal(t, http.StatusOK, <-done)
	assert.Len(t, started, 0)
}
