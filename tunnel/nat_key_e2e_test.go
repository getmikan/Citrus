package tunnel_test

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sendAs(src netip.AddrPort, inName, inUser string, dst *e2eNode, data []byte) {
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.SOCKS5,
		SrcIP:   src.Addr(),
		SrcPort: src.Port(),
		DstIP:   dst.addr.Addr(),
		DstPort: dst.addr.Port(),
		InName:  inName,
		InUser:  inUser,
	}
	packet := &e2ePacket{data: bytes.Clone(data), src: net.UDPAddrFromAddrPort(src)}
	tunnel.Tunnel.HandleUDPPacket(packet, metadata)
	time.Sleep(20 * time.Millisecond)
}

// A UDP session is chosen for its inbound and user: a packet from the same
// client address on another inbound, or as another user, is routed on its
// own and does not ride on the other's session.
func TestUDPSessionKeyedByInboundAndUser(t *testing.T) {
	proxies := map[string]C.Proxy{
		"DIRECT": adapter.NewProxy(outbound.NewDirect()),
		"REJECT": adapter.NewProxy(outbound.NewReject()),
	}
	inName, err := rules.ParseRule("IN-NAME", "blocked-in", "REJECT", nil, nil)
	require.NoError(t, err)
	inUser, err := rules.ParseRule("IN-USER", "blocked-user", "REJECT", nil, nil)
	require.NoError(t, err)
	match, err := rules.ParseRule("MATCH", "", "DIRECT", nil, nil)
	require.NoError(t, err)
	tunnel.UpdateProxies(proxies, nil)
	tunnel.UpdateRules([]C.Rule{inName, inUser, match}, nil, nil)
	tunnel.OnRunning()
	t.Cleanup(func() {
		tunnel.OnSuspend()
		tunnel.UpdateRules(nil, nil, nil)
		closeUDPSessions()
	})

	t.Run("inbound", func(t *testing.T) {
		node := newE2ENode(t)
		client := netip.MustParseAddrPort("192.168.1.20:40001")
		sendAs(client, "open-in", "", node, []byte("allowed"))
		sendAs(client, "blocked-in", "", node, []byte("from the blocked inbound"))
		assert.Equal(t, [][]byte{[]byte("allowed")}, node.received())
	})

	t.Run("user", func(t *testing.T) {
		node := newE2ENode(t)
		client := netip.MustParseAddrPort("192.168.1.20:40002")
		sendAs(client, "shared-in", "alice", node, []byte("alice"))
		sendAs(client, "shared-in", "blocked-user", node, []byte("as the blocked user"))
		assert.Equal(t, [][]byte{[]byte("alice")}, node.received())
	})
}

func TestNatKey(t *testing.T) {
	packet := &e2ePacket{src: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.0.0.1:5000"))}
	plain := C.NatKey(packet, &C.Metadata{})
	assert.Equal(t, "10.0.0.1:5000", plain, "a packet with no inbound identity keeps the address key")

	keys := map[string]bool{plain: true}
	for _, m := range []*C.Metadata{
		{InName: "a"},
		{InName: "b"},
		{InName: "a", InUser: "u"},
		{InName: "a", InUser: "v"},
		{InName: "a", InIP: netip.MustParseAddr("127.0.0.1"), InPort: 1080},
		{InName: "a", InIP: netip.MustParseAddr("127.0.0.1"), InPort: 1081},
	} {
		k := C.NatKey(packet, m)
		assert.False(t, keys[k], "duplicate key %q", k)
		keys[k] = true
		assert.Equal(t, k, C.NatKey(packet, m))
	}
}
