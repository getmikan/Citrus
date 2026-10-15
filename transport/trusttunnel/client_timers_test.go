package trusttunnel

import (
	"context"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/v2ray"

	"github.com/metacubex/http"
)

func newTimersClient(t *testing.T, options ClientOptions) (*Client, error) {
	t.Helper()
	options.Dialer = &countingDialer{}
	options.Server = "127.0.0.1:1"
	options.TLSConfig = &v2ray.TLSConfig{Host: "example.com", SkipCertVerify: true}
	client, err := NewClient(context.Background(), options)
	if err == nil {
		t.Cleanup(func() { _ = client.Close() })
	}
	return client, err
}

// Every client carries its own timers, and the HTTP/2 transport gets them.
func TestClientSessionTimers(t *testing.T) {
	tests := []struct {
		name                                 string
		options                              ClientOptions
		pingInterval, pingTimeout, handshake time.Duration
	}{
		{
			name:         "defaults",
			pingInterval: 15 * time.Second,
			pingTimeout:  15 * time.Second,
			handshake:    DefaultSessionHandshakeTimeout,
		},
		{
			name:         "custom",
			options:      ClientOptions{PingInterval: 30 * time.Second, PingTimeout: 5 * time.Second, HandshakeTimeout: 3 * time.Second},
			pingInterval: 30 * time.Second,
			pingTimeout:  5 * time.Second,
			handshake:    3 * time.Second,
		},
		{
			name:         "pings off",
			options:      ClientOptions{PingInterval: -time.Second},
			pingInterval: 0,
			pingTimeout:  15 * time.Second,
			handshake:    DefaultSessionHandshakeTimeout,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := newTimersClient(t, test.options)
			if err != nil {
				t.Fatal(err)
			}
			if client.pingInterval != test.pingInterval || client.pingTimeout != test.pingTimeout || client.handshakeTimeout != test.handshake {
				t.Fatalf("timers = %v/%v/%v, want %v/%v/%v",
					client.pingInterval, client.pingTimeout, client.handshakeTimeout,
					test.pingInterval, test.pingTimeout, test.handshake)
			}
			h2 := client.roundTripper.(*http.Transport).HTTP2
			if h2.SendPingTimeout != test.pingInterval || h2.PingTimeout != test.pingTimeout {
				t.Fatalf("HTTP2Config = %v/%v, want %v/%v", h2.SendPingTimeout, h2.PingTimeout, test.pingInterval, test.pingTimeout)
			}
		})
	}
}

func TestClientSessionTimersRejectNegativeTimeouts(t *testing.T) {
	for _, options := range []ClientOptions{
		{PingTimeout: -time.Second},
		{HandshakeTimeout: -time.Second},
	} {
		if _, err := newTimersClient(t, options); err == nil {
			t.Fatalf("NewClient(%+v) accepted a negative timeout", options)
		}
	}
}

// Two clients in one process keep their own ping timers: a frozen path
// closes the session of the client with short pings and leaves the session
// of the client with pings turned off alone.
func TestClientPingTimersArePerClient(t *testing.T) {
	server := startEchoServer(t)
	proxy := startFreezeProxy(t, server.Listener.Addr().String())
	fast, _ := newProxiedClient(t, proxy.listener.Addr().String(), 200*time.Millisecond, 300*time.Millisecond)
	quiet, quietDialer := newProxiedClient(t, proxy.listener.Addr().String(), -1, 0)

	fastConn, err := fast.Dial(context.Background(), "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer fastConn.Close()
	quietConn, err := quiet.Dial(context.Background(), "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer quietConn.Close()
	echoOnce(t, fastConn, "fast")
	echoOnce(t, quietConn, "quiet")

	proxy.setFrozen(true)
	failed := make(chan error, 1)
	go func() {
		_, err := fastConn.Read(make([]byte, 1))
		failed <- err
	}()
	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("read on a dead session returned no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the client with short pings kept a dead session")
	}
	proxy.setFrozen(false)

	echoOnce(t, quietConn, "still here")
	if got := quietDialer.dials.Load(); got != 1 {
		t.Fatalf("the client without pings dialed %d connections, want its session kept", got)
	}
}
