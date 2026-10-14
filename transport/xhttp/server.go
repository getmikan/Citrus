package xhttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/httputils"
	N "github.com/metacubex/mihomo/common/net"

	"github.com/metacubex/http"
)

type ServerOption struct {
	Config
	ConnHandler func(net.Conn, *http.Request)
	HttpHandler http.Handler
	// ReportsAuthentication: ConnHandler calls the function returned by
	// OnAuthenticated for its request once the inner protocol has
	// authenticated the client, and a packet-up/stream-up session stays
	// pending (capped, reaped, upload-limited) until then. Without it the
	// session leaves the pending state with the first upload byte, which
	// proves nothing.
	ReportsAuthentication bool
}

type authenticatedKey struct{}

// OnAuthenticated returns the function the ConnHandler of a server with
// ReportsAuthentication calls once the client is authenticated, or nil.
func OnAuthenticated(r *http.Request) func() {
	fn, _ := r.Context().Value(authenticatedKey{}).(func())
	return fn
}

type httpServerConn struct {
	mu      sync.Mutex
	w       http.ResponseWriter
	flusher http.Flusher
	reader  io.ReadCloser
	closed  bool
	done    chan struct{}
	once    sync.Once
}

func newHTTPServerConn(w http.ResponseWriter, r io.ReadCloser) *httpServerConn {
	flusher, _ := w.(http.Flusher)
	return &httpServerConn{
		w:       w,
		flusher: flusher,
		reader:  r,
		done:    make(chan struct{}),
	}
}

func (c *httpServerConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *httpServerConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, io.ErrClosedPipe
	}

	n, err := c.w.Write(b)
	if err == nil && c.flusher != nil {
		c.flusher.Flush()
	}
	return n, err
}

func (c *httpServerConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		close(c.done)
	})
	return c.reader.Close()
}

func (c *httpServerConn) Wait() <-chan struct{} {
	return c.done
}

// Limits on sessions that have not delivered any upload data yet. Such a
// session costs a map entry, an upload queue and a reaper goroutine, and the
// inner protocol (VLESS) has not seen a single byte from it, so nothing has
// been authenticated. Xray-core only has the 30-second reaper for sessions
// whose download GET never arrives; here the same deadline also covers a
// session whose GET has arrived but whose upload never brings any data, and
// the number of such sessions is capped. Once upload data has reached the
// inner handler the session is no longer pending and is never reaped by these
// limits, so long-lived downloads are unaffected.
var (
	maxPendingSessions    = 4096
	pendingSessionTimeout = 30 * time.Second
	// pendingUploadTimeout bounds reading the body of a packet-up upload to a
	// pending session: the client has not authenticated, it must not hold a
	// request open by trickling its body.
	pendingUploadTimeout = 15 * time.Second
	// maxPendingUploadBytes bounds the upload payload accepted by all pending
	// sessions together (counted until a session leaves the pending state or
	// is removed); beyond it a new pending upload gets 503. A client sends
	// little before it authenticates, the VLESS header and its first data.
	maxPendingUploadBytes = 64 << 20
)

// maxSessionIDLength bounds the session ID taken from the request. Xray-core
// and Citrus clients send 32 hex digits, a UUID or a configured 16-32
// character string by default.
const maxSessionIDLength = 256

type httpSession struct {
	uploadQueue *UploadQueue
	activated   chan struct{} // closed once the session is no longer pending
	activate    sync.Once
	closed      chan struct{} // closed once the session is removed from the handler
	// guarded by requestHandler.mu
	pending      bool
	pendingBytes int  // upload payload accepted while pending
	uploads      int  // packet-up uploads in progress while pending
	downloading  bool // a session download is being served
}

func newHTTPSession(maxPackets int) *httpSession {
	return &httpSession{
		uploadQueue: NewUploadQueue(maxPackets),
		activated:   make(chan struct{}),
		closed:      make(chan struct{}),
		pending:     true,
	}
}

// sessionReader feeds the inner handler from the upload queue and marks the
// session active on the first byte it delivers.
type sessionReader struct {
	*UploadQueue
	h *requestHandler
	s *httpSession
}

func (r *sessionReader) Read(b []byte) (int, error) {
	n, err := r.UploadQueue.Read(b)
	if n > 0 && !r.h.reportsAuthentication {
		r.h.activateSession(r.s)
	}
	return n, err
}

type requestHandler struct {
	config      Config
	connHandler func(net.Conn, *http.Request)
	httpHandler http.Handler

	reportsAuthentication bool

	xPaddingBytes        Range
	scMaxEachPostBytes   Range
	scStreamUpServerSecs Range
	scMaxBufferedPosts   Range

	mu           sync.Mutex
	sessions     map[string]*httpSession
	pending      int // sessions that have not left the pending state yet
	pendingBytes int // sum of httpSession.pendingBytes
}

func NewServerHandler(opt ServerOption) (http.Handler, error) {
	xPaddingBytes, err := opt.Config.GetNormalizedXPaddingBytes()
	if err != nil {
		return nil, err
	}
	scMaxEachPostBytes, err := opt.Config.GetNormalizedScMaxEachPostBytes()
	if err != nil {
		return nil, err
	}
	scStreamUpServerSecs, err := opt.Config.GetNormalizedScStreamUpServerSecs()
	if err != nil {
		return nil, err
	}
	scMaxBufferedPosts, err := opt.Config.GetNormalizedScMaxBufferedPosts()
	if err != nil {
		return nil, err
	}
	return &requestHandler{
		config:                opt.Config,
		connHandler:           opt.ConnHandler,
		httpHandler:           opt.HttpHandler,
		reportsAuthentication: opt.ReportsAuthentication,
		xPaddingBytes:         xPaddingBytes,
		scMaxEachPostBytes:    scMaxEachPostBytes,
		scStreamUpServerSecs:  scStreamUpServerSecs,
		scMaxBufferedPosts:    scMaxBufferedPosts,
		sessions:              map[string]*httpSession{},
	}, nil
}

func (h *requestHandler) activateSession(s *httpSession) {
	s.activate.Do(func() {
		h.mu.Lock()
		h.leavePendingLocked(s)
		h.mu.Unlock()
		close(s.activated)
	})
}

// leavePendingLocked drops s from the pending accounting. h.mu must be held.
func (h *requestHandler) leavePendingLocked(s *httpSession) {
	if s.pending {
		s.pending = false
		h.pending--
		h.pendingBytes -= s.pendingBytes
		s.pendingBytes = 0
	}
}

// beginPendingUpload admits a packet-up upload. It returns whether the
// session is pending, and false for ok when a pending session already has as
// many uploads in progress as its queue holds packets: more could not be
// queued anyway, and each holds a request and its body.
func (h *requestHandler) beginPendingUpload(s *httpSession) (pending, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !s.pending {
		return false, true
	}
	if s.uploads >= h.scMaxBufferedPosts.Max {
		return true, false
	}
	s.uploads++
	return true, true
}

func (h *requestHandler) endPendingUpload(s *httpSession) {
	h.mu.Lock()
	s.uploads--
	h.mu.Unlock()
}

// reservePendingBytes counts n payload bytes against the pending budget; it
// fails when the session is still pending and the budget is spent.
func (h *requestHandler) reservePendingBytes(s *httpSession, n int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !s.pending {
		return true
	}
	if h.pendingBytes+n > maxPendingUploadBytes {
		return false
	}
	h.pendingBytes += n
	s.pendingBytes += n
	return true
}

// beginDownload marks the session download as served; a second concurrent
// download of the same session would run a second inner handler on the same
// upload queue.
func (h *requestHandler) beginDownload(s *httpSession) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s.downloading {
		return false
	}
	s.downloading = true
	return true
}

// upsertSession returns the session for sessionID, creating it if needed. It
// returns nil when the session does not exist and too many sessions are
// already pending.
func (h *requestHandler) upsertSession(sessionID string) *httpSession {
	h.mu.Lock()
	defer h.mu.Unlock()

	s, ok := h.sessions[sessionID]
	if ok {
		return s
	}
	if h.pending >= maxPendingSessions {
		return nil
	}

	s = newHTTPSession(h.scMaxBufferedPosts.Max)
	h.sessions[sessionID] = s
	h.pending++

	// Reap sessions that never deliver any upload data (e.g. from probing).
	// Xray-core's reaper stops at the download GET; this one waits for data.
	timeout := pendingSessionTimeout // read here, not in the goroutine, which may outlive a test that changes it
	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			h.deleteSession(sessionID, s)
		case <-s.activated:
		case <-s.closed:
		}
	}()

	return s
}

// deleteSession removes s if it is still the session registered under
// sessionID, so a late close never drops a newer session with the same ID.
func (h *requestHandler) deleteSession(sessionID string, s *httpSession) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.sessions[sessionID] != s {
		return
	}
	delete(h.sessions, sessionID)
	h.leavePendingLocked(s)
	_ = s.uploadQueue.Close()
	close(s.closed)
}

func (h *requestHandler) getSession(sessionID string) *httpSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[sessionID]
}

func (h *requestHandler) normalizedMode() string {
	if h.config.Mode == "" {
		return "auto"
	}
	return h.config.Mode
}

func (h *requestHandler) allowStreamOne() bool {
	switch h.normalizedMode() {
	case "auto", "stream-one", "stream-up":
		return true
	default:
		return false
	}
}

func (h *requestHandler) allowSessionDownload() bool {
	switch h.normalizedMode() {
	case "auto", "stream-up", "packet-up":
		return true
	default:
		return false
	}
}

func (h *requestHandler) allowStreamUpUpload() bool {
	switch h.normalizedMode() {
	case "auto", "stream-up":
		return true
	default:
		return false
	}
}

func (h *requestHandler) allowPacketUpUpload() bool {
	switch h.normalizedMode() {
	case "auto", "packet-up":
		return true
	default:
		return false
	}
}

func (h *requestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := h.config.NormalizedPath()
	if h.httpHandler != nil && !strings.HasPrefix(r.URL.Path, path) {
		h.httpHandler.ServeHTTP(w, r)
		return
	}

	if h.config.Host != "" && !equalHost(r.Host, h.config.Host) {
		http.NotFound(w, r)
		return
	}

	if !strings.HasPrefix(r.URL.Path, path) {
		http.NotFound(w, r)
		return
	}

	h.config.WriteResponseHeader(w, r.Method, r.Header)
	length := h.xPaddingBytes.Rand()
	config := XPaddingConfig{Length: length}

	if h.config.XPaddingObfsMode {
		config.Placement = h.config.xPaddingObfsPlacement("")
		config.Method = PaddingMethod(h.config.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: PlacementHeader,
			Header:    "X-Padding",
		}
	}

	h.config.ApplyXPaddingToResponse(w, config)

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	paddingValue, _ := h.config.ExtractXPaddingFromRequest(r, h.config.XPaddingObfsMode)
	if !h.config.IsPaddingValid(paddingValue, h.xPaddingBytes.Min, h.xPaddingBytes.Max, PaddingMethod(h.config.XPaddingMethod)) {
		http.Error(w, "invalid xpadding", http.StatusBadRequest)
		return
	}
	obfsPaddingAccepted := h.config.XPaddingObfsMode && paddingValue != ""
	sessionId, seqStr := h.config.ExtractMetaFromRequest(r, path)
	if len(sessionId) > maxSessionIDLength {
		http.Error(w, "invalid xhttp session", http.StatusBadRequest)
		return
	}

	var currentSession *httpSession
	if sessionId != "" {
		currentSession = h.upsertSession(sessionId)
		if currentSession == nil {
			http.Error(w, "too many pending sessions", http.StatusServiceUnavailable)
			return
		}
	}

	// stream-up upload: POST /path/{session}
	if r.Method != http.MethodGet && sessionId != "" && seqStr == "" && h.allowStreamUpUpload() {
		httpSC := newHTTPServerConn(w, r.Body)
		err := currentSession.uploadQueue.Push(Packet{
			Reader: httpSC,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}

		// magic header instructs nginx + apache to not buffer response body
		w.Header().Set("X-Accel-Buffering", "no")
		// A web-compliant header telling all middleboxes to disable caching.
		// Should be able to prevent overloading the cache, or stop CDNs from
		// teeing the response stream into their cache, causing slowdowns.
		w.Header().Set("Cache-Control", "no-store")
		if !h.config.NoSSEHeader {
			// magic header to make the HTTP middle box consider this as SSE to disable buffer
			w.Header().Set("Content-Type", "text/event-stream")
		}
		w.WriteHeader(http.StatusOK)

		rc := http.NewResponseController(w)
		_ = rc.EnableFullDuplex() // http1 need to enable full duplex manually
		_ = rc.Flush()            // force flush the response header

		hasLegacyRefererCompatMarker := r.Header.Get("Referer") != ""
		if (hasLegacyRefererCompatMarker || obfsPaddingAccepted) && h.scStreamUpServerSecs.Max > 0 {
			go func() {
				for {
					_, err := httpSC.Write(bytes.Repeat([]byte{'X'}, int(h.xPaddingBytes.Rand())))
					if err != nil {
						break
					}
					time.Sleep(time.Duration(h.scStreamUpServerSecs.Rand()) * time.Second)
				}
			}()
		}

		select {
		case <-r.Context().Done():
		case <-httpSC.Wait():
		}

		_ = httpSC.Close()
		return
	}

	// packet-up upload: {any method} /path/{session}/{seq}
	// As in Xray-core, a request with a seq is an upload whatever its method
	// (uplink-http-method): CDNs that pass only GET/HEAD to the origin, or
	// answer 405 to POST, still get through with GET/PUT/... uploads.
	if sessionId != "" && seqStr != "" && h.allowPacketUpUpload() {
		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid xhttp seq", http.StatusBadRequest)
			return
		}
		pending, ok := h.beginPendingUpload(currentSession)
		if !ok {
			http.Error(w, "too many pending uploads", http.StatusServiceUnavailable)
			return
		}
		if pending {
			defer h.endPendingUpload(currentSession)
			// the client is not authenticated yet: the body must come in time
			_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(pendingUploadTimeout))
		}
		scMaxEachPostBytes := h.scMaxEachPostBytes.Max
		dataPlacement := h.config.GetNormalizedServerUplinkDataPlacement()
		var headerPayload []byte
		if dataPlacement == PlacementAuto || dataPlacement == PlacementHeader {
			uplinkDataKey := h.config.GetNormalizedUplinkDataKey(PlacementHeader)
			var headerPayloadChunks []string
			for i := 0; true; i++ {
				chunk := r.Header.Get(fmt.Sprintf("%s-%d", uplinkDataKey, i))
				if chunk == "" {
					break
				}
				headerPayloadChunks = append(headerPayloadChunks, chunk)
			}
			headerPayloadEncoded := strings.Join(headerPayloadChunks, "")
			headerPayload, err = base64.RawURLEncoding.DecodeString(headerPayloadEncoded)
			if err != nil {
				http.Error(w, "invalid base64 in header's payload", http.StatusBadRequest)
				return
			}
		}

		var cookiePayload []byte
		if dataPlacement == PlacementAuto || dataPlacement == PlacementCookie {
			uplinkDataKey := h.config.GetNormalizedUplinkDataKey(PlacementCookie)
			var cookiePayloadChunks []string
			for i := 0; true; i++ {
				cookieName := fmt.Sprintf("%s_%d", uplinkDataKey, i)
				if c, _ := r.Cookie(cookieName); c != nil {
					cookiePayloadChunks = append(cookiePayloadChunks, c.Value)
				} else {
					break
				}
			}
			cookiePayloadEncoded := strings.Join(cookiePayloadChunks, "")
			cookiePayload, err = base64.RawURLEncoding.DecodeString(cookiePayloadEncoded)
			if err != nil {
				http.Error(w, "invalid base64 in cookies' payload", http.StatusBadRequest)
				return
			}
		}

		var bodyPayload []byte
		var releaseBody func()
		if dataPlacement == PlacementAuto || dataPlacement == PlacementBody {
			if r.ContentLength > int64(scMaxEachPostBytes) {
				http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
				return
			}
			bodyPayload, releaseBody, err = readPacketBody(r.Body, r.ContentLength, scMaxEachPostBytes)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
			if pending {
				_ = http.NewResponseController(w).SetReadDeadline(time.Time{})
			}
		}

		var payload []byte
		release := releaseBody // only while payload is bodyPayload itself
		switch dataPlacement {
		case PlacementHeader:
			payload = headerPayload
		case PlacementCookie:
			payload = cookiePayload
		case PlacementBody:
			payload = bodyPayload
		case PlacementAuto:
			if len(headerPayload) == 0 && len(cookiePayload) == 0 {
				payload = bodyPayload // the usual case: no copy
				break
			}
			payload = headerPayload
			payload = append(payload, cookiePayload...)
			payload = append(payload, bodyPayload...)
			if releaseBody != nil {
				releaseBody()
				release = nil
			}
		}

		if len(payload) > h.scMaxEachPostBytes.Max {
			if release != nil {
				release()
			}
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}

		if !h.reservePendingBytes(currentSession, len(payload)) {
			if release != nil {
				release()
			}
			http.Error(w, "too much pending upload data", http.StatusServiceUnavailable)
			return
		}

		err = currentSession.uploadQueue.Push(Packet{
			Seq:     seq,
			Payload: payload,
			Release: release,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if len(bodyPayload) == 0 || r.Method == http.MethodGet {
			// Methods without a body are usually cached by default, and so are GET responses.
			w.Header().Set("Cache-Control", "no-store")
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	// stream-up/packet-up download: GET /path/{session}
	if r.Method == http.MethodGet && sessionId != "" && seqStr == "" && h.allowSessionDownload() {
		if !h.beginDownload(currentSession) {
			http.Error(w, "session download already in progress", http.StatusConflict)
			return
		}
		if h.reportsAuthentication {
			s := currentSession
			r = r.WithContext(context.WithValue(r.Context(), authenticatedKey{}, func() { h.activateSession(s) }))
		}
		// magic header instructs nginx + apache to not buffer response body
		w.Header().Set("X-Accel-Buffering", "no")
		// A web-compliant header telling all middleboxes to disable caching.
		// Should be able to prevent overloading the cache, or stop CDNs from
		// teeing the response stream into their cache, causing slowdowns.
		w.Header().Set("Cache-Control", "no-store")
		if !h.config.NoSSEHeader {
			// magic header to make the HTTP middle box consider this as SSE to disable buffer
			w.Header().Set("Content-Type", "text/event-stream")
		}
		w.WriteHeader(http.StatusOK)

		rc := http.NewResponseController(w)
		_ = rc.EnableFullDuplex() // http1 need to enable full duplex manually
		_ = rc.Flush()            // force flush the response header

		httpSC := newHTTPServerConn(w, r.Body)
		conn := &Conn{
			writer: httpSC,
			reader: &sessionReader{UploadQueue: currentSession.uploadQueue, h: h, s: currentSession},
			onClose: func() {
				h.deleteSession(sessionId, currentSession)
			},
		}
		httputils.SetAddrFromRequest(&conn.NetAddr, r)

		go h.connHandler(N.NewDeadlineConn(conn), r)

		select {
		case <-r.Context().Done():
		case <-httpSC.Wait():
		case <-currentSession.closed: // reaped before any upload data arrived
		}

		_ = conn.Close()
		return
	}

	// stream-one: POST /path
	if r.Method != http.MethodGet && sessionId == "" && seqStr == "" && h.allowStreamOne() {
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)

		rc := http.NewResponseController(w)
		_ = rc.EnableFullDuplex() // http1 need to enable full duplex manually
		_ = rc.Flush()            // force flush the response header

		httpSC := newHTTPServerConn(w, r.Body)
		conn := &Conn{
			writer: httpSC,
			reader: httpSC,
		}
		httputils.SetAddrFromRequest(&conn.NetAddr, r)

		go h.connHandler(N.NewDeadlineConn(conn), r)

		select {
		case <-r.Context().Done():
		case <-httpSC.Wait():
		}

		_ = conn.Close()
		return
	}

	http.NotFound(w, r)
}

// packetBodyPool recycles the bodies of packet-up uploads (up to
// sc-max-each-post-bytes, 1 MB by default, per request). Reading them with
// io.ReadAll grew a fresh slice from 512 bytes for every POST: about twice the
// body in copies, the same again in zeroed memory, and the GC work for it, a
// large part of the server's CPU for a packet-up upload.
var packetBodyPool sync.Pool // of *[]byte

// minPooledPacketBody: smaller bodies are allocated exactly; a pooled buffer
// is only used for a body of at least half its capacity, so a small packet
// waiting in an upload queue never pins a large buffer.
const minPooledPacketBody = 32 << 10

// readPacketBody reads a packet-up request body of at most limit bytes. When
// the length is declared, the body is read into a buffer of that size, pooled
// for large bodies; release (nil when not pooled) gives the buffer back once
// the payload is no longer used.
func readPacketBody(r io.Reader, contentLength int64, limit int) (payload []byte, release func(), err error) {
	if contentLength < 0 || contentLength > int64(limit) {
		// unknown length (HTTP/1.1 chunked, or HTTP/2 without content-length);
		// the caller rejects a declared length above the limit.
		payload, err = io.ReadAll(io.LimitReader(r, int64(limit)+1))
		return payload, nil, err
	}
	n := int(contentLength)
	if n < minPooledPacketBody {
		payload = make([]byte, n)
		if _, err = io.ReadFull(r, payload); err != nil {
			return nil, nil, err
		}
		return payload, nil, nil
	}
	bp, _ := packetBodyPool.Get().(*[]byte)
	if bp == nil || cap(*bp) < n || cap(*bp)/2 > n {
		b := make([]byte, n)
		bp = &b
	}
	payload = (*bp)[:n]
	if _, err = io.ReadFull(r, payload); err != nil {
		packetBodyPool.Put(bp)
		return nil, nil, err
	}
	return payload, func() { packetBodyPool.Put(bp) }, nil
}

func splitNonEmpty(s string) []string {
	raw := strings.Split(s, "/")
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func equalHost(a, b string) bool {
	a = strings.ToLower(a)
	b = strings.ToLower(b)

	if ah, _, err := net.SplitHostPort(a); err == nil {
		a = ah
	}
	if bh, _, err := net.SplitHostPort(b); err == nil {
		b = bh
	}

	return a == b
}
