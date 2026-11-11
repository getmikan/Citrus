package trusttunnel

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

type earlyTicketCache struct {
	tls.ClientSessionCache
	received chan struct{}
}

func (c *earlyTicketCache) Put(key string, session *tls.ClientSessionState) {
	c.ClientSessionCache.Put(key, session)
	if session != nil {
		select {
		case c.received <- struct{}{}:
		default:
		}
	}
}

func TestHTTP3ZeroRTTRequiresExplicitOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "cover") }))
			defer backend.Close()
			_, addr := startFallbackServer(t, backend, time.Second, enabled)
			cache := &earlyTicketCache{ClientSessionCache: tls.NewLRUClientSessionCache(4), received: make(chan struct{}, 4)}
			clientTLS := &tls.Config{InsecureSkipVerify: true, ServerName: "cover.example", ClientSessionCache: cache}
			for attempt := 0; attempt < 2; attempt++ {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				states := make(chan quic.ConnectionState, 1)
				transport := &http3.Transport{
					TLSClientConfig: clientTLS,
					Dial: func(ctx context.Context, addr string, cfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
						conn, err := quic.DialAddrEarly(ctx, addr, cfg, qcfg)
						if err != nil {
							return nil, err
						}
						go func() {
							select {
							case <-conn.HandshakeComplete():
								states <- conn.ConnectionState()
							case <-conn.Context().Done():
							}
						}()
						return conn, nil
					},
				}
				t.Cleanup(func() { transport.Close() })
				req, err := http.NewRequestWithContext(ctx, http3.MethodGet0RTT, "https://"+addr+"/", nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := transport.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || string(body) != "cover" {
					t.Fatalf("response changed: %q, %v", body, err)
				}
				select {
				case state := <-states:
					if attempt == 1 && !state.TLS.DidResume {
						t.Fatal("test did not exercise a resumed session")
					}
					if state.Used0RTT != (enabled && attempt == 1) {
						t.Fatalf("attempt %d Used0RTT=%v with zero-rtt=%v", attempt, state.Used0RTT, enabled)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if attempt == 0 {
					select {
					case <-cache.received:
					case <-ctx.Done():
						t.Fatal("server did not issue a session ticket")
					}
				}
				transport.Close()
				cancel()
			}
		})
	}
}
