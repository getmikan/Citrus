package trusttunnel

import (
	"context"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

// CONNECT in another spelling must not get past the check either: a lenient backend
// treats any spelling of CONNECT as CONNECT.
func TestFallbackConnectAnySpelling(t *testing.T) {
	for _, protocol := range []string{"HTTP/1.1", "HTTP/2", "HTTP/3"} {
		for _, method := range []string{"connect", "Connect"} {
			t.Run(protocol+"/"+method, func(t *testing.T) {
				got := make(chan int, 1)
				backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if !strings.EqualFold(r.Method, "CONNECT") {
						w.WriteHeader(405)
						return
					}
					conn, buf, err := w.(http.Hijacker).Hijack()
					if err != nil {
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
					data := make([]byte, 1024)
					n, _ := buf.Read(data)
					if n > 0 {
						_, _ = conn.Write(data[:n])
					}
					got <- n
				}))
				defer backend.Close()
				s, address := startFallbackServer(t, backend, time.Second)
				s.UpdateUsers(map[string]string{"alice": "secret"})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				reader, writer := io.Pipe()
				defer reader.Close()
				defer writer.Close()
				go func() { _, _ = io.WriteString(writer, "SSH-2.0-client-tunnel-payload\r\n") }()
				req := (&http.Request{Method: method, URL: &url.URL{Scheme: "https", Host: address, Path: "/"}, Host: "10.0.0.5:22", Header: make(http.Header), Body: reader, ContentLength: -1}).WithContext(ctx)
				resp, err := fallbackClients(t)[protocol].RoundTrip(req)
				if err != nil {
					return // refused before any tunnel: fine
				}
				defer resp.Body.Close()
				body := make([]byte, 64)
				n, _ := io.ReadAtLeast(resp.Body, body, 1)
				select {
				case b := <-got:
					if b > 0 {
						t.Errorf("backend got %d client bytes; status %d; echoed %q", b, resp.StatusCode, body[:n])
					}
				case <-time.After(1500 * time.Millisecond):
				}
				if resp.StatusCode != http.StatusBadGateway {
					t.Errorf("status %d, want 502", resp.StatusCode)
				}
			})
		}
	}
}
