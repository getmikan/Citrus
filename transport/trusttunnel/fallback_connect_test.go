package trusttunnel

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

// This backend actually accepts CONNECT and echoes bytes from the connection.
// A cover backend which happens to be a proxy must not enable a second tunnel.
func TestFallbackConnectAcceptingBackend(t *testing.T) {
	for _, protocol := range []string{"HTTP/1.1", "HTTP/2", "HTTP/3"} {
		for _, credentials := range []string{"", "alice:wrong"} {
			t.Run(protocol+"/"+credentials, func(t *testing.T) {
				type observation struct {
					host     string
					length   int64
					transfer []string
					bytes    int
				}
				seen := make(chan observation, 1)
				backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					conn, buffer, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
					data := make([]byte, 1024)
					n, _ := buffer.Read(data)
					if n > 0 {
						_, _ = conn.Write(data[:n])
					}
					seen <- observation{r.Host, r.ContentLength, r.TransferEncoding, n}
				}))
				defer backend.Close()
				wantHost := strings.TrimPrefix(backend.URL, "http://")
				s, address := startFallbackServer(t, backend, time.Second)
				s.UpdateUsers(map[string]string{"alice": "secret"})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				reader, writer := io.Pipe()
				defer reader.Close()
				defer writer.Close()
				// Do not close the writer until after RoundTrip: HTTP/2 body is
				// a live tunnel stream, not a completed buffered upload.
				go func() { _, _ = io.WriteString(writer, "SSH-2.0-client-tunnel-payload\r\n") }()
				request := (&http.Request{
					Method: http.MethodConnect,
					URL:    &url.URL{Scheme: "https", Host: address},
					Host:   "10.0.0.5:22",
					Header: make(http.Header),
					Body:   reader, ContentLength: -1,
				}).WithContext(ctx)
				if credentials != "" {
					request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
				}
				response, err := fallbackClients(t)[protocol].RoundTrip(request)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if response.StatusCode != http.StatusBadGateway {
					t.Fatalf("backend opened a tunnel: status=%d", response.StatusCode)
				}
				body, err := io.ReadAll(response.Body)
				if err != nil || strings.Contains(string(body), "client-tunnel-payload") {
					t.Fatalf("response body=%q err=%v", body, err)
				}
				select {
				case observation := <-seen:
					if observation.host != wantHost || observation.length != 0 || len(observation.transfer) != 0 || observation.bytes != 0 {
						t.Fatalf("CONNECT payload reached backend: %+v", observation)
					}
				case <-ctx.Done():
					t.Fatal("accepted backend connection was not closed")
				}
				if !waitSlotsFree(s, time.Second) {
					t.Fatal("CONNECT kept a fallback slot")
				}
			})
		}
	}
}

func TestFallbackConnectResponseCodes(t *testing.T) {
	for _, status := range []int{200, 201, 204, 299, 101, 400, 403, 405, 407, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			defer backend.Close()
			s := newFallbackService(t, backend)
			request := httptest.NewRequest(http.MethodConnect, "https://cover.example/", nil)
			response := &http.Response{Request: request, StatusCode: status, Header: make(http.Header)}
			err := s.fallbackProxy.ModifyResponse(response)
			blocked := status == 101 || (status >= 200 && status < 300)
			if (err != nil) != blocked {
				t.Fatalf("status=%d err=%v", status, err)
			}
		})
	}
}

func TestValidateFallback(t *testing.T) {
	for _, address := range []string{"", "127.0.0.1:8080", "cover.example:80", "[::1]:8080", "[fe80::1%eth0]:80"} {
		if err := ValidateFallback(address); err != nil {
			t.Errorf("%q: %v", address, err)
		}
	}
	for _, address := range []string{"http://127.0.0.1:8080", "127.0.0.1", ":8080", "host:", "host:0", "host:-1", "host:65536", "host:http", "host:80/path", " host:80", "host name:80", "host?query:80"} {
		if err := ValidateFallback(address); err == nil {
			t.Errorf("accepted %q", address)
		}
	}
}
