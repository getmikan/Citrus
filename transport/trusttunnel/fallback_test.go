package trusttunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/http/httptrace"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/sing/common/logger"
	"github.com/metacubex/tls"
	xhttp2 "golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func newFallbackService(t *testing.T, backend *httptest.Server) *Service {
	t.Helper()
	s := NewService(ServiceOptions{Ctx: context.Background(), Fallback: strings.TrimPrefix(backend.URL, "http://")})
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// serveFallbackAsync runs serveFallback the way a server would, treating an
// http.ErrAbortHandler panic as an aborted response, and reports whether the
// response was aborted.
func serveFallbackAsync(s *Service, writer http.ResponseWriter, request *http.Request) <-chan bool {
	done := make(chan bool, 1)
	go func() {
		aborted := false
		defer func() {
			if recovered := recover(); recovered != nil {
				if recovered != http.ErrAbortHandler {
					panic(recovered)
				}
				aborted = true
			}
			done <- aborted
		}()
		s.serveFallback(writer, request)
	}()
	return done
}

func TestFallbackForwardedHeaders(t *testing.T) {
	var header http.Header
	var host string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Clone()
		host = r.Host
	}))
	defer backend.Close()
	s := newFallbackService(t, backend)

	request := httptest.NewRequest("GET", "https://cover.example/", nil)
	request.Header.Set("Forwarded", "for=198.51.100.77;proto=http")
	request.Header.Set("X-Forwarded-For", "198.51.100.77")
	request.Header.Set("X-Forwarded-Proto", "http")
	request.Header.Set("X-Forwarded-Host", "attacker.example")
	request.Header.Set("Proxy-Authorization", "Basic invalid")
	request.Header.Set("Connection", "X-Probe")
	request.Header.Set("X-Probe", "should disappear")
	recorder := httptest.NewRecorder()
	s.serveFallback(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if host != "cover.example" {
		t.Errorf("Host = %q, want cover.example", host)
	}
	for _, name := range []string{"Forwarded", "Proxy-Authorization", "X-Probe"} {
		if value := header.Get(name); value != "" {
			t.Errorf("%s reached backend: %q", name, value)
		}
	}
	// httptest.NewRequest uses 192.0.2.1 as the client address and sets TLS for https.
	want := map[string]string{
		"X-Forwarded-For":   "192.0.2.1",
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Host":  "cover.example",
	}
	for name, value := range want {
		if got := header.Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

func TestFallbackResponseBodyStall(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer backend.Close()
	s := newFallbackService(t, backend)
	s.fallbackIdleTimeout = 100 * time.Millisecond

	recorder := httptest.NewRecorder()
	select {
	case aborted := <-serveFallbackAsync(s, recorder, httptest.NewRequest("GET", "https://cover.example/", nil)):
		if !aborted {
			t.Error("truncated response was not aborted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stalled response body was not aborted")
	}
	if recorder.Body.String() != "partial" {
		t.Errorf("body = %q, want the bytes sent before the stall", recorder.Body.String())
	}
}

func TestFallbackRequestBodyStall(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer backend.Close()
	s := newFallbackService(t, backend)
	s.fallbackIdleTimeout = 100 * time.Millisecond
	// The idle stage cancels the backend request and the handler then answers
	// 502. The stuck stage (aborting writes to a client that stopped reading) is
	// not what this test checks: with its default of one more idle period it
	// raced the 502 on a loaded runner and cut the answer off, so push it past
	// the client's deadline. TestFallbackClientStopsReading covers that stage.
	s.fallbackStuckTimeout = time.Minute

	t.Run("handler", func(t *testing.T) {
		body, bodyWriter := io.Pipe()
		defer bodyWriter.Close()
		recorder := httptest.NewRecorder()
		select {
		case aborted := <-serveFallbackAsync(s, recorder, httptest.NewRequest("POST", "https://cover.example/", body)):
			if aborted {
				t.Error("request that stalled before the response was aborted instead of answered")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("stalled request body was not aborted")
		}
		if recorder.Code != http.StatusBadGateway {
			t.Errorf("status = %d, want 502", recorder.Code)
		}
	})

	t.Run("server", func(t *testing.T) {
		front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.serveFallback(w, r)
		}))
		defer front.Close()
		conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		// Promise 100 bytes, send 5, then go quiet.
		_, err = conn.Write([]byte("POST / HTTP/1.1\r\nHost: cover.example\r\nContent-Length: 100\r\n\r\nhello"))
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("no response for stalled upload: %v", err)
		}
		if response.StatusCode != http.StatusBadGateway {
			t.Errorf("status = %d, want 502", response.StatusCode)
		}
	})
}

func TestFallbackSlowStreamKeepsWorking(t *testing.T) {
	const chunks = 5
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < chunks; i++ {
			_, _ = w.Write([]byte("x"))
			w.(http.Flusher).Flush()
			time.Sleep(50 * time.Millisecond)
		}
	}))
	defer backend.Close()
	s := newFallbackService(t, backend)
	// The stream lasts longer than the idle limit, but no single gap exceeds it.
	s.fallbackIdleTimeout = 150 * time.Millisecond

	recorder := httptest.NewRecorder()
	s.serveFallback(recorder, httptest.NewRequest("GET", "https://cover.example/", nil))
	if recorder.Body.String() != strings.Repeat("x", chunks) {
		t.Errorf("body = %q, want %d chunks", recorder.Body.String(), chunks)
	}
}

func TestFallbackConcurrencyLimit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	s := newFallbackService(t, backend)
	for i := 0; i < cap(s.fallbackSlots); i++ {
		s.fallbackSlots <- struct{}{}
	}

	recorder := httptest.NewRecorder()
	s.serveFallback(recorder, httptest.NewRequest("GET", "https://cover.example/", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}

	<-s.fallbackSlots
	recorder = httptest.NewRecorder()
	s.serveFallback(recorder, httptest.NewRequest("GET", "https://cover.example/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status after a slot freed = %d, want 200", recorder.Code)
	}
}

func TestFallbackUpgradeOutlivesIdleTimeout(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = rw.Flush()
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = rw.WriteString(line)
		_ = rw.Flush()
	}))
	defer backend.Close()
	s := newFallbackService(t, backend)
	s.fallbackIdleTimeout = 100 * time.Millisecond
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.serveFallback(w, r)
	}))
	defer front.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: cover.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", response.StatusCode)
	}

	// Stay quiet for longer than the idle limit; the upgraded connection must survive.
	time.Sleep(300 * time.Millisecond)
	_, err = conn.Write([]byte("ping\n"))
	if err != nil {
		t.Fatal(err)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("upgraded connection closed after idle period: %v", err)
	}
	if line != "ping\n" {
		t.Errorf("echo = %q, want %q", line, "ping\n")
	}
}

// startFallbackServer runs the real TrustTunnel service (HTTP/1.1 and HTTP/2 over
// TLS, HTTP/3 over QUIC) with the given fallback backend and returns its address.
func startFallbackServer(t *testing.T, backend *httptest.Server, idleTimeout time.Duration) (*Service, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cover.example"},
		DNSNames:     []string{"cover.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}

	tcpListener, udpConn := listenTCPAndUDP(t)
	s := NewService(ServiceOptions{
		Ctx:      context.Background(),
		Logger:   logger.NOP(),
		Fallback: strings.TrimPrefix(backend.URL, "http://"),
	})
	s.fallbackIdleTimeout = idleTimeout
	// Like listener/trusttunnel: a certificate and no NextProtos.
	err = s.Start(tcpListener, udpConn, &tls.Config{
		Certificates: []tls.Certificate{certificate},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, tcpListener.Addr().String()
}

func fallbackClients(t *testing.T) map[string]http.RoundTripper {
	clientTLS := &tls.Config{InsecureSkipVerify: true, ServerName: "cover.example"}
	h1 := new(http.Protocols)
	h1.SetHTTP1(true)
	h2 := new(http.Protocols)
	h2.SetHTTP2(true)
	h1Transport := &http.Transport{TLSClientConfig: clientTLS.Clone(), Protocols: h1}
	h2Transport := &http.Transport{TLSClientConfig: clientTLS.Clone(), Protocols: h2}
	h3Transport := &http3.Transport{TLSClientConfig: clientTLS.Clone()}
	t.Cleanup(func() {
		h1Transport.CloseIdleConnections()
		h2Transport.CloseIdleConnections()
		_ = h3Transport.Close()
	})
	return map[string]http.RoundTripper{"HTTP/1.1": h1Transport, "HTTP/2": h2Transport, "HTTP/3": h3Transport}
}

func waitSlotsFree(s *Service, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(s.fallbackSlots) == 0 {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestFallbackClientStopsReading(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat("x", 64<<10))
		for i := 0; i < 4096; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer backend.Close()
	s, address := startFallbackServer(t, backend, 100*time.Millisecond)

	for name, transport := range fallbackClients(t) {
		t.Run(name, func(t *testing.T) {
			request, err := http.NewRequest("GET", "https://"+address+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Host = "cover.example"
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.ProtoMajor != int(name[5]-'0') {
				t.Fatalf("negotiated %s, want %s", response.Proto, name)
			}
			// Read the headers only, then stop reading; the server's writes block
			// once the flow-control windows and socket buffers fill up.
			if len(s.fallbackSlots) == 0 {
				t.Fatal("fallback request is not in flight")
			}
			// HTTP/1.1 over TLS may take up to 5s more after the abort: closing the
			// connection makes crypto/tls try to send close_notify with its own 5s
			// write deadline to a client that is not reading.
			if !waitSlotsFree(s, 8*time.Second) {
				t.Fatalf("handler still holds a slot after the idle timeout (slots=%d)", len(s.fallbackSlots))
			}
		})
	}
}

// listenTCPAndUDP opens TCP and UDP on one port, as the inbound does. The free TCP
// port may be one Windows keeps from UDP (the ranges Hyper-V and WinNAT exclude),
// so another port is tried then.
func listenTCPAndUDP(t *testing.T) (net.Listener, net.PacketConn) {
	t.Helper()
	// Free TCP ports come out sequentially, so a run of them can all fall inside
	// one excluded UDP range; take a free UDP port first and open TCP on it, and
	// only fall back to the other order.
	var err error
	for i := 0; i < 20; i++ {
		var udpConn net.PacketConn
		udpConn, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		var tcpListener net.Listener
		tcpListener, err = net.Listen("tcp", udpConn.LocalAddr().String())
		if err == nil {
			return tcpListener, udpConn
		}
		_ = udpConn.Close()

		tcpListener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		udpConn, err = net.ListenPacket("udp", tcpListener.Addr().String())
		if err == nil {
			return tcpListener, udpConn
		}
		_ = tcpListener.Close()
	}
	t.Fatal(err)
	return nil, nil
}

func TestFallbackConnectReachesBackend(t *testing.T) {
	var method, host string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, host = r.Method, r.Host
		w.Header().Set("Server", "cover")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = io.WriteString(w, "not here")
	}))
	defer backend.Close()
	_, address := startFallbackServer(t, backend, time.Minute)

	for name, transport := range fallbackClients(t) {
		if name == "HTTP/3" {
			continue // the HTTP/3 client does not send plain CONNECT requests
		}
		t.Run(name, func(t *testing.T) {
			method, host = "", ""
			request := &http.Request{
				Method: http.MethodConnect,
				URL:    &url.URL{Scheme: "https", Host: address},
				Host:   "cover.example:443",
				Header: make(http.Header),
			}
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			if response.StatusCode != http.StatusMethodNotAllowed || response.Header.Get("Server") != "cover" || string(body) != "not here" {
				t.Errorf("got %d Server=%q body=%q, want the backend's own response", response.StatusCode, response.Header.Get("Server"), body)
			}
			if method != http.MethodConnect || host != "cover.example:443" {
				t.Errorf("backend saw %s %q, want CONNECT cover.example:443", method, host)
			}
		})
	}
}

func TestFallbackEarlyAnswerToStalledUpload(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer backend.Close()
	s := newFallbackService(t, backend)
	s.fallbackIdleTimeout = 100 * time.Millisecond
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.serveFallback(w, r)
	}))
	defer front.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// Promise a large body, send a few bytes, then go quiet. The server drains
	// the body before it can send the early answer, so the answer must survive
	// the idle timeout instead of being aborted with it.
	_, err = conn.Write([]byte("POST / HTTP/1.1\r\nHost: cover.example\r\nContent-Length: 1000000\r\n\r\nhello"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("early answer lost: %v", err)
	}
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", response.StatusCode)
	}
	if !waitSlotsFree(s, 2*time.Second) {
		t.Errorf("handler still holds a slot (slots=%d)", len(s.fallbackSlots))
	}
}

func TestFallbackUploadsReuseConnection(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	}))
	defer backend.Close()
	_, address := startFallbackServer(t, backend, time.Minute)

	for name, transport := range fallbackClients(t) {
		t.Run(name, func(t *testing.T) {
			for i := 0; i < 3; i++ {
				payload := strings.Repeat("y", 100<<10)
				request, err := http.NewRequest("POST", "https://"+address+"/", strings.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				request.Host = "cover.example"
				// The transport redials silently when the server drops the connection, so
				// reuse is checked explicitly. The HTTP/3 transport does not report it.
				reused := false
				request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
					GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
				}))
				response, err := transport.RoundTrip(request)
				if err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || string(body) != payload {
					t.Fatalf("request %d: echoed %d bytes, err=%v", i, len(body), err)
				}
				if i > 0 && name != "HTTP/3" && !reused {
					t.Errorf("request %d opened a new connection instead of reusing the first", i)
				}
			}
		})
	}
}

// TestFallbackRefusesPriorKnowledgeH2 checks that with a fallback the server speaks
// HTTP/2 only after negotiating h2, as a real HTTPS site does: a prober that sends the
// HTTP/2 preface over TLS that negotiated http/1.1, or nothing, gets an HTTP/1 answer.
func TestFallbackRefusesPriorKnowledgeH2(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	_, address := startFallbackServer(t, backend, time.Minute)

	// The client connection preface followed by an empty SETTINGS frame.
	preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + "\x00\x00\x00\x04\x00\x00\x00\x00\x00"
	for _, offer := range [][]string{{"http/1.1"}, nil} {
		conn, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true, NextProtos: offer})
		if err != nil {
			t.Fatalf("offer %v: %v", offer, err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = io.WriteString(conn, preface); err != nil {
			t.Fatalf("offer %v: %v", offer, err)
		}
		head := make([]byte, 9)
		_, err = io.ReadFull(conn, head)
		_ = conn.Close()
		if err != nil {
			t.Fatalf("offer %v: no answer to the preface: %v", offer, err)
		}
		if !strings.HasPrefix(string(head), "HTTP/1.") {
			t.Errorf("offer %v: answered %q, want an HTTP/1 response, not HTTP/2 frames", offer, head)
		}
	}
}

func TestFallbackCloseStopsUpgrade(t *testing.T) {
	backendClosed := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		defer close(backendClosed)
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = rw.Flush()
		for {
			line, err := rw.ReadString('\n')
			if err != nil {
				return
			}
			_, _ = rw.WriteString(line)
			_ = rw.Flush()
		}
	}))
	defer backend.Close()
	s, address := startFallbackServer(t, backend, time.Minute)

	conn, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: cover.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", response.StatusCode)
	}
	_, _ = io.WriteString(conn, "before-close\n")
	if line, err := reader.ReadString('\n'); err != nil || line != "before-close\n" {
		t.Fatalf("echo before close: %q, %v", line, err)
	}

	_ = s.Close()
	_ = s.Close() // a second Close must be harmless

	select {
	case <-backendClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("backend connection still open after Service.Close")
	}
	if !waitSlotsFree(s, 3*time.Second) {
		t.Errorf("handler still holds a slot after Service.Close (slots=%d)", len(s.fallbackSlots))
	}
	_, _ = io.WriteString(conn, "after-close\n")
	if line, err := reader.ReadString('\n'); err == nil && line == "after-close\n" {
		t.Error("upgraded connection still forwards traffic after Service.Close")
	}
}

func TestFallbackNegotiatesALPN(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	_, address := startFallbackServer(t, backend, time.Minute)

	for _, test := range []struct {
		offer []string
		want  string
	}{
		{[]string{"h2", "http/1.1"}, "h2"},
		{[]string{"http/1.1"}, "http/1.1"},
		{[]string{"h2"}, "h2"},
		{nil, ""},
	} {
		conn, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true, NextProtos: test.offer})
		if err != nil {
			t.Fatalf("offer %v: %v", test.offer, err)
		}
		if got := conn.ConnectionState().NegotiatedProtocol; got != test.want {
			t.Errorf("offer %v: negotiated %q, want %q", test.offer, got, test.want)
		}
		_ = conn.Close()
	}
}

func TestFallbackPerSourceLimit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	s := newFallbackService(t, backend)
	// httptest.NewRequest comes from 192.0.2.1.
	busy, _ := fallbackSource("192.0.2.1:1234")
	s.fallbackSources[busy] = fallbackMaxPerSource

	recorder := httptest.NewRecorder()
	s.serveFallback(recorder, httptest.NewRequest("GET", "https://cover.example/", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status for a source at its limit = %d, want 503", recorder.Code)
	}
	if len(s.fallbackSlots) != 0 {
		t.Fatalf("a refused source took a global slot (slots=%d)", len(s.fallbackSlots))
	}

	other := httptest.NewRequest("GET", "https://cover.example/", nil)
	other.RemoteAddr = "198.51.100.7:4321"
	recorder = httptest.NewRecorder()
	s.serveFallback(recorder, other)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status for another source = %d, want 200", recorder.Code)
	}
	if len(s.fallbackSources) != 1 {
		t.Fatalf("finished request still counted against its source: %v", s.fallbackSources)
	}
}

func TestFallbackSourceGroupsIPv6ByPrefix(t *testing.T) {
	a, okA := fallbackSource("[2001:db8:1:2::1]:443")
	b, okB := fallbackSource("[2001:db8:1:2:ffff::9]:443")
	c, okC := fallbackSource("[2001:db8:1:3::1]:443")
	v4, okV4 := fallbackSource("[::ffff:192.0.2.1]:443")
	if !okA || !okB || !okC || !okV4 {
		t.Fatal("valid addresses were not parsed")
	}
	if a != b || a == c {
		t.Errorf("IPv6 sources: %v %v %v, want the /64 shared and the next /64 apart", a, b, c)
	}
	if v4.String() != "192.0.2.1/32" {
		t.Errorf("IPv4-mapped source = %v, want 192.0.2.1/32", v4)
	}
	if _, ok := fallbackSource("not an address"); ok {
		t.Error("garbage parsed as a source")
	}
}

func TestFallbackDialRefusesMetadataAddresses(t *testing.T) {
	for _, address := range []string{"169.254.169.254:80", "[fe80::1]:80", "0.0.0.0:80", "[::]:80", "224.0.0.1:80", "[::ffff:169.254.169.254]:80", "[fd00:ec2::254]:80", "100.100.100.200:80"} {
		if err := fallbackDialControl("tcp4", address, nil); err == nil {
			t.Errorf("dial to %s allowed", address)
		}
	}
	for _, address := range []string{"127.0.0.1:8080", "[::1]:8080", "10.0.0.5:80", "203.0.113.9:443", "100.100.100.201:80", "[fd00:ec2::1]:80"} {
		if err := fallbackDialControl("tcp4", address, nil); err != nil {
			t.Errorf("dial to %s refused: %v", address, err)
		}
	}

	// A name that resolves to a refused address is caught when the transport dials.
	s := NewService(ServiceOptions{Ctx: context.Background(), Fallback: "169.254.169.254:80"})
	t.Cleanup(func() { _ = s.Close() })
	started := time.Now()
	recorder := httptest.NewRecorder()
	s.serveFallback(recorder, httptest.NewRequest("GET", "https://cover.example/", nil))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", recorder.Code)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("refused dial took %s, as if it was attempted", elapsed)
	}
}

func TestAuthFailureLogLimiter(t *testing.T) {
	var limiter logLimiter
	now := time.Unix(1000, 0)
	if ok, n := limiter.allow(now, 10*time.Second); !ok || n != 0 {
		t.Fatalf("first message: %v %d", ok, n)
	}
	for i := 0; i < 3; i++ {
		if ok, _ := limiter.allow(now.Add(time.Duration(i+1)*time.Second), 10*time.Second); ok {
			t.Fatalf("message %d inside the interval was logged", i)
		}
	}
	if ok, n := limiter.allow(now.Add(10*time.Second), 10*time.Second); !ok || n != 3 {
		t.Fatalf("after the interval: %v suppressed=%d, want true 3", ok, n)
	}
}

// TestFallbackHTTP2LooksLikeCaddy checks the parts of the HTTP/2 fingerprint the
// fallback controls, measured against Caddy 2.11: the header list limit in SETTINGS,
// and Date written by the front server after the backend's headers.
func TestFallbackHTTP2LooksLikeCaddy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", "Mon, 01 Jan 2001 00:00:00 GMT")
		w.Header().Set("Server", "Caddy")
		w.Header().Set("Etag", `"x"`)
		_, _ = io.WriteString(w, "cover")
	}))
	defer backend.Close()
	_, address := startFallbackServer(t, backend, time.Minute)

	conn, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = io.WriteString(conn, xhttp2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	framer := xhttp2.NewFramer(conn, conn)
	if err = framer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "cover.example"}, {Name: ":path", Value: "/"}} {
		_ = encoder.WriteField(field)
	}
	if err = framer.WriteHeaders(xhttp2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndStream: true, EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	var headerList uint32
	var names []string
	var date string
	decoder := hpack.NewDecoder(4096, func(field hpack.HeaderField) {
		names = append(names, field.Name)
		if field.Name == "date" {
			date = field.Value
		}
	})
	for names == nil {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		switch frame := frame.(type) {
		case *xhttp2.SettingsFrame:
			if value, ok := frame.Value(xhttp2.SettingMaxHeaderListSize); ok {
				headerList = value
			}
			if !frame.IsAck() {
				_ = framer.WriteSettingsAck()
			}
		case *xhttp2.HeadersFrame:
			if _, err := decoder.Write(frame.HeaderBlockFragment()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if headerList != 16704 {
		t.Errorf("MAX_HEADER_LIST_SIZE = %d, want Caddy's 16704", headerList)
	}
	if len(names) == 0 || names[len(names)-1] != "date" {
		t.Errorf("header order %v, want date last", names)
	}
	if strings.Contains(date, "2001") {
		t.Errorf("backend Date %q passed through", date)
	}
}

// Unknown users are refused, including an empty password; known users with an
// intentionally empty password remain valid. Timing is not asserted by this test.
func TestVerifyUnknownUser(t *testing.T) {
	s := NewService(ServiceOptions{Ctx: context.Background()})
	s.UpdateUsers(map[string]string{"alice": "secret", "empty": "", "unicode": "風" + strings.Repeat("x", 1000)})
	basic := func(user, password string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	}
	for user, password := range map[string]string{"alice": "secret", "empty": "", "unicode": "風" + strings.Repeat("x", 1000)} {
		if got, ok := s.verify(basic(user, password)); !ok || got.Name() != user {
			t.Fatalf("correct credentials for %q refused: entry=%v, ok=%v", user, got, ok)
		}
	}
	for _, auth := range []string{basic("alice", "wrong"), basic("bob", "secret"), basic("bob", ""), basic("", ""), ""} {
		if _, ok := s.verify(auth); ok {
			t.Errorf("%q accepted", auth)
		}
	}
}

// Exercise the public handler, including the no-fallback compatibility path.
func TestFallbackAuthenticationRouting(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		t.Run(map[bool]string{false: "without_fallback", true: "with_fallback"}[fallback], func(t *testing.T) {
			var backendCalls atomic.Int32
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				backendCalls.Add(1)
				w.WriteHeader(http.StatusAccepted)
			}))
			defer backend.Close()
			options := ServiceOptions{Ctx: context.Background(), Logger: logger.NOP()}
			if fallback {
				options.Fallback = strings.TrimPrefix(backend.URL, "http://")
			}
			s := NewService(options)
			defer s.Close()
			s.UpdateUsers(map[string]string{"alice": "secret"})
			for _, credentials := range []string{"", "alice:wrong", "bob:secret", "alice:secret"} {
				request := httptest.NewRequest(http.MethodGet, "https://cover.example/", nil)
				if credentials != "" {
					request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
				}
				before := backendCalls.Load()
				recorder := httptest.NewRecorder()
				s.ServeHTTP(recorder, request)
				want := http.StatusProxyAuthRequired
				wantCalls := before
				if credentials == "alice:secret" {
					want = http.StatusMethodNotAllowed // valid credentials, but GET cannot create a tunnel
				} else if fallback {
					want = http.StatusAccepted
					wantCalls++
				}
				if recorder.Code != want || backendCalls.Load() != wantCalls {
					t.Fatalf("credentials %q: status=%d calls=%d, want status=%d calls=%d", credentials, recorder.Code, backendCalls.Load(), want, wantCalls)
				}
			}
		})
	}
}
