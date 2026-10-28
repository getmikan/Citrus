package tunnel_test

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/egress"
	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reaches hands one TCP connection for host:port (or the IP literal when
// host is empty) from an inbound of typ to the tunnel and reports whether
// the listener received it.
func reaches(t *testing.T, typ C.Type, guard C.EgressGuard, host string) bool {
	t.Helper()
	ln := listen(t)
	port := ln.Addr().(*net.TCPAddr).Port

	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- struct{}{}
		_ = c.Close()
	}()

	client, server := net.Pipe()
	defer client.Close()
	metadata := &C.Metadata{
		NetWork:     C.TCP,
		Type:        typ,
		InName:      "server-in",
		InUser:      "alice",
		EgressGuard: guard,
		SrcIP:       netip.MustParseAddr("198.51.100.7"),
		SrcPort:     40000,
		Host:        host,
		DstPort:     uint16(port),
	}
	if host == "" {
		metadata.DstIP = netip.MustParseAddr("127.0.0.1")
	}
	done := make(chan struct{})
	go func() {
		tunnel.Tunnel.HandleTCPConn(server, metadata)
		close(done)
	}()

	var ok bool
	select {
	case <-accepted:
		ok = true
	case <-done: // refused without a dial
	case <-time.After(3 * time.Second):
	}
	_ = client.Close()
	_ = ln.Close()
	<-done
	return ok
}

func withEgress(t *testing.T, o egress.Options) {
	t.Helper()
	old := egress.CurrentOptions()
	egress.SetOptions(o)
	t.Cleanup(func() { egress.SetOptions(old) })
}

// An explicit rule that sends the loopback to DIRECT does not open it to the
// users of a server inbound, for an IP literal or a domain that resolves to
// it; the local client inbounds are routed as before.
func TestEgressGuardRulesCannotBypass(t *testing.T) {
	withEgress(t, egress.Options{Enable: true})
	loopback := &sequenceResolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	direct, err := RC.NewIPCIDR("127.0.0.0/8", "DIRECT")
	require.NoError(t, err)
	setupTunnel(t, []C.Rule{direct, RC.NewMatch("DIRECT")}, loopback, loopback)

	for _, typ := range []C.Type{C.VLESS, C.TROJAN, C.SHADOWSOCKS, C.ANYTLS} {
		assert.False(t, reaches(t, typ, C.EgressGuardDefault, ""), "%s: IP literal", typ)
		assert.False(t, reaches(t, typ, C.EgressGuardDefault, "rebind.example"), "%s: resolved domain", typ)
	}
	assert.True(t, reaches(t, C.SOCKS5, C.EgressGuardDefault, ""), "client inbound, IP literal")
	assert.True(t, reaches(t, C.SOCKS5, C.EgressGuardDefault, "rebind.example"), "client inbound, domain")
}

// The ways to open it on purpose: the listener's egress-guard: false and the
// allow-list. And egress-guard: true closes a client listener.
func TestEgressGuardOverrides(t *testing.T) {
	withEgress(t, egress.Options{Enable: true})
	loopback := &sequenceResolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	setupTunnel(t, []C.Rule{RC.NewMatch("DIRECT")}, loopback, loopback)

	assert.True(t, reaches(t, C.VLESS, C.EgressGuardOff, "rebind.example"))
	assert.False(t, reaches(t, C.SOCKS5, C.EgressGuardOn, "rebind.example"))

	egress.SetOptions(egress.Options{Enable: true, AllowIPs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	assert.True(t, reaches(t, C.VLESS, C.EgressGuardDefault, "rebind.example"))

	egress.SetOptions(egress.Options{Enable: false})
	assert.True(t, reaches(t, C.VLESS, C.EgressGuardDefault, ""))
	assert.False(t, reaches(t, C.SOCKS5, C.EgressGuardOn, ""))
}
