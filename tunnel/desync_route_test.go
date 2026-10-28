package tunnel_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// firstRecord reads the first TLS record of a connection, accepted by ln,
// and reports whether it holds the whole ClientHello.
func firstRecord(ln net.Listener) <-chan bool {
	whole := make(chan bool, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(whole)
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		header := make([]byte, 5)
		if _, err := io.ReadFull(c, header); err != nil || header[0] != 0x16 {
			close(whole)
			return
		}
		body := make([]byte, binary.BigEndian.Uint16(header[3:]))
		if _, err := io.ReadFull(c, body); err != nil {
			close(whole)
			return
		}
		whole <- len(body) >= 4 && len(body) >= 4+(int(body[1])<<16|int(body[2])<<8|int(body[3]))
	}()
	return whole
}

// routeHello sends a ClientHello for host through the tunnel.
func routeHello(t *testing.T, ln net.Listener, host string) <-chan bool {
	t.Helper()
	whole := firstRecord(ln)
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.SOCKS5,
		SrcIP:   netip.MustParseAddr("192.0.2.1"),
		SrcPort: 40000,
		Host:    host,
		DstPort: uint16(ln.Addr().(*net.TCPAddr).Port),
	}
	go tunnel.Tunnel.HandleTCPConn(server, metadata)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tls.Client(client, &tls.Config{ServerName: host, InsecureSkipVerify: true}).HandshakeContext(ctx)
	}()
	return whole
}

// A rule sends one domain to the desync outbound, everything else to DIRECT:
// only the first arrives with its ClientHello split into records.
func TestDesyncRuleRouting(t *testing.T) {
	local := &sequenceResolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	setupTunnel(t, []C.Rule{
		RC.NewDomainSuffix("youtube.test", "desync-yt"),
		RC.NewMatch("DIRECT"),
	}, local, local)
	desync, err := adapter.ParseProxy(map[string]any{"name": "desync-yt", "type": "desync", "tlsrec": "1+s"})
	require.NoError(t, err)
	tunnel.UpdateProxies(map[string]C.Proxy{
		"DIRECT":    adapter.NewProxy(outbound.NewDirect()),
		"REJECT":    adapter.NewProxy(outbound.NewReject()),
		"desync-yt": desync,
	}, nil)

	ln := listen(t)
	defer ln.Close()
	whole, ok := <-routeHello(t, ln, "www.youtube.test")
	require.True(t, ok, "the desync connection did not arrive")
	assert.False(t, whole, "a rule-routed desync connection must arrive fragmented")

	ln2 := listen(t)
	defer ln2.Close()
	whole, ok = <-routeHello(t, ln2, "other.test")
	require.True(t, ok, "the DIRECT connection did not arrive")
	assert.True(t, whole, "DIRECT must stay untouched")
}
