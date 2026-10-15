package inbound_test

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/authevent"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The authevent handler is process-global and the inbound tests run in
// parallel, so a single handler fans events out to subscribers that each wait
// for the events of their own listener.
var authEvents struct {
	once        sync.Once
	access      sync.Mutex
	subscribers map[chan authevent.Event]struct{}
}

func subscribeAuthEvents(t *testing.T) <-chan authevent.Event {
	authEvents.once.Do(func() {
		authEvents.subscribers = make(map[chan authevent.Event]struct{})
		authevent.SetHandler(func(e authevent.Event) {
			authEvents.access.Lock()
			defer authEvents.access.Unlock()
			for ch := range authEvents.subscribers {
				select {
				case ch <- e:
				default:
				}
			}
		})
	})
	ch := make(chan authevent.Event, 64)
	authEvents.access.Lock()
	authEvents.subscribers[ch] = struct{}{}
	authEvents.access.Unlock()
	t.Cleanup(func() {
		authEvents.access.Lock()
		delete(authEvents.subscribers, ch)
		authEvents.access.Unlock()
	})
	return ch
}

func waitAuthEvent(t *testing.T, events <-chan authevent.Event, protocol, local string) authevent.Event {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Protocol == protocol && e.Local == local {
				return e
			}
		case <-timeout:
			t.Fatalf("no %s auth event for %s", protocol, local)
			return authevent.Event{}
		}
	}
}

// dialRejected opens a proxied connection with credentials the inbound does
// not know and pushes a request through, so that the server reads them.
func dialRejected(proxy C.ProxyAdapter) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: remoteAddr, DstPort: 80})
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	_, _ = conn.Read(make([]byte, 1))
}

func startAuthEventInbound(t *testing.T, in C.InboundListener) (netip.AddrPort, *TestTunnel) {
	tunnel := NewHttpTestTunnel()
	t.Cleanup(func() { _ = tunnel.Close() })
	require.NoError(t, in.Listen(tunnel))
	t.Cleanup(func() { _ = in.Close() })
	addrPort, err := netip.ParseAddrPort(in.Address())
	require.NoError(t, err)
	return addrPort, tunnel
}

func TestInboundAuthEvent_TrustTunnel(t *testing.T) {
	events := subscribeAuthEvents(t)
	in, err := inbound.NewTrustTunnel(&inbound.TrustTunnelOption{
		BaseOption:  inbound.BaseOption{NameStr: "trusttunnel_authevent", Listen: "127.0.0.1", Port: "0"},
		Users:       []inbound.AuthUser{{Username: "test", Password: userUUID}},
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	})
	require.NoError(t, err)
	addrPort, tunnel := startAuthEventInbound(t, in)

	out, err := outbound.NewTrustTunnel(outbound.TrustTunnelOption{
		BasicOption: outbound.BasicOption{DialerForAPI: tunnel.NewDialer(), TunnelForAPI: tunnel},
		Name:        "trusttunnel_authevent",
		Server:      addrPort.Addr().String(),
		Port:        int(addrPort.Port()),
		UserName:    "test",
		Password:    "wrong",
		Fingerprint: tlsFingerprint,
	})
	require.NoError(t, err)
	defer out.Close()

	dialRejected(out)
	e := waitAuthEvent(t, events, "trusttunnel", addrPort.String())
	assert.Equal(t, authevent.ReasonWrongCredentials, e.Reason)
	assert.Equal(t, "CONNECT", e.Method)
	assert.NotEmpty(t, e.Remote)
}

func TestInboundAuthEvent_AnyTLS(t *testing.T) {
	events := subscribeAuthEvents(t)
	in, err := inbound.NewAnyTLS(&inbound.AnyTLSOption{
		BaseOption:  inbound.BaseOption{NameStr: "anytls_authevent", Listen: "127.0.0.1", Port: "0"},
		Users:       map[string]string{"test": userUUID},
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	})
	require.NoError(t, err)
	addrPort, tunnel := startAuthEventInbound(t, in)

	out, err := outbound.NewAnyTLS(outbound.AnyTLSOption{
		BasicOption: outbound.BasicOption{DialerForAPI: tunnel.NewDialer(), TunnelForAPI: tunnel},
		Name:        "anytls_authevent",
		Server:      addrPort.Addr().String(),
		Port:        int(addrPort.Port()),
		Password:    "wrong",
		Fingerprint: tlsFingerprint,
	})
	require.NoError(t, err)
	defer out.Close()

	dialRejected(out)
	e := waitAuthEvent(t, events, "anytls", addrPort.String())
	assert.Equal(t, authevent.ReasonWrongCredentials, e.Reason)
	assert.NotEmpty(t, e.Remote)
}

func TestInboundAuthEvent_Vless(t *testing.T) {
	events := subscribeAuthEvents(t)
	in, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:  inbound.BaseOption{NameStr: "vless_authevent", Listen: "127.0.0.1", Port: "0"},
		Users:       []inbound.VlessUser{{Username: "test", UUID: userUUID}},
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	})
	require.NoError(t, err)
	addrPort, tunnel := startAuthEventInbound(t, in)

	out, err := outbound.NewVless(outbound.VlessOption{
		BasicOption: outbound.BasicOption{DialerForAPI: tunnel.NewDialer(), TunnelForAPI: tunnel},
		Name:        "vless_authevent",
		Server:      addrPort.Addr().String(),
		Port:        int(addrPort.Port()),
		UUID:        "00000000-0000-4000-8000-000000000001",
		TLS:         true,
		Fingerprint: tlsFingerprint,
	})
	require.NoError(t, err)
	defer out.Close()

	dialRejected(out)
	e := waitAuthEvent(t, events, "vless", addrPort.String())
	assert.Equal(t, authevent.ReasonWrongCredentials, e.Reason)
	assert.NotEmpty(t, e.Remote)
}

func TestInboundAuthEvent_Trojan(t *testing.T) {
	events := subscribeAuthEvents(t)
	in, err := inbound.NewTrojan(&inbound.TrojanOption{
		BaseOption:  inbound.BaseOption{NameStr: "trojan_authevent", Listen: "127.0.0.1", Port: "0"},
		Users:       []inbound.TrojanUser{{Username: "test", Password: userUUID}},
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	})
	require.NoError(t, err)
	addrPort, tunnel := startAuthEventInbound(t, in)

	out, err := outbound.NewTrojan(outbound.TrojanOption{
		BasicOption: outbound.BasicOption{DialerForAPI: tunnel.NewDialer(), TunnelForAPI: tunnel},
		Name:        "trojan_authevent",
		Server:      addrPort.Addr().String(),
		Port:        int(addrPort.Port()),
		Password:    "wrong",
		Fingerprint: tlsFingerprint,
	})
	require.NoError(t, err)
	defer out.Close()

	dialRejected(out)
	e := waitAuthEvent(t, events, "trojan", addrPort.String())
	assert.Equal(t, authevent.ReasonWrongCredentials, e.Reason)
	assert.NotEmpty(t, e.Remote)
}
