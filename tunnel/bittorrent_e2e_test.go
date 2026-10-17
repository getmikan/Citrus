package tunnel_test

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
	snifferTypes "github.com/metacubex/mihomo/constant/sniffer"
	"github.com/metacubex/mihomo/rules"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// End to end through the tunnel: a BitTorrent client socket on the LAN talks
// to a DHT node A and a peer B, with PROTOCOL,bittorrent,REJECT in the rules
// and MATCH,DIRECT behind it. A and B are real UDP sockets on loopback.

var (
	e2eDHTPing = []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe")
	// uTP ST_SYN with the extension bits extension, as libutp sends it
	e2eUTPSyn = []byte{
		0x41, 0x02, 0x77, 0xef, 0x0b, 0x1f, 0xb1, 0xf6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
		0xc2, 0x33, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
)

type e2ePacket struct {
	data []byte
	src  *net.UDPAddr
}

func (p *e2ePacket) Data() []byte                                { return p.data }
func (p *e2ePacket) WriteBack(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (p *e2ePacket) Drop()                                       {}
func (p *e2ePacket) LocalAddr() net.Addr                         { return p.src }

type e2eNode struct {
	conn *net.UDPConn
	addr netip.AddrPort
}

func newE2ENode(t *testing.T) *e2eNode {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return &e2eNode{conn: conn, addr: conn.LocalAddr().(*net.UDPAddr).AddrPort()}
}

// received collects what arrives until nothing has for a while
func (n *e2eNode) received() [][]byte {
	var got [][]byte
	buf := make([]byte, 2048)
	for {
		_ = n.conn.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
		size, _, err := n.conn.ReadFromUDP(buf)
		if err != nil {
			return got
		}
		got = append(got, bytes.Clone(buf[:size]))
	}
}

func send(src netip.AddrPort, dst *e2eNode, data []byte) {
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.TUN,
		SrcIP:   src.Addr(),
		SrcPort: src.Port(),
		DstIP:   dst.addr.Addr(),
		DstPort: dst.addr.Port(),
	}
	packet := &e2ePacket{data: bytes.Clone(data), src: net.UDPAddrFromAddrPort(src)}
	tunnel.Tunnel.HandleUDPPacket(packet, metadata)
	// keep the order of arrival at the sockets readable in the assertions
	time.Sleep(20 * time.Millisecond)
}

func setupBitTorrentTunnel(t *testing.T, bittorrentTarget string) {
	t.Helper()

	proxies := map[string]C.Proxy{
		"DIRECT": adapter.NewProxy(outbound.NewDirect()),
		"REJECT": adapter.NewProxy(outbound.NewReject()),
	}
	protocolRule, err := rules.ParseRule("PROTOCOL", "bittorrent", bittorrentTarget, nil, nil)
	require.NoError(t, err)
	matchRule, err := rules.ParseRule("MATCH", "", "DIRECT", nil, nil)
	require.NoError(t, err)

	dispatcher, err := sniffer.NewDispatcher(&sniffer.Config{
		Enable:      true,
		ParsePureIp: true,
		Sniffers: map[snifferTypes.Type]sniffer.SnifferConfig{
			snifferTypes.BitTorrent: {},
		},
	})
	require.NoError(t, err)

	tunnel.UpdateProxies(proxies, nil)
	tunnel.UpdateRules([]C.Rule{protocolRule, matchRule}, nil, nil)
	tunnel.UpdateSniffer(dispatcher)
	tunnel.OnRunning()
	t.Cleanup(func() {
		tunnel.OnSuspend()
		tunnel.UpdateRules(nil, nil, nil)
		closeUDPSessions()
	})
}

// closeUDPSessions closes the UDP sessions a test left open. Taking them from
// the connection manager also orders their setup (which reads the resolver
// globals) before whatever the next test changes; without it the race
// detector reports those reads against the next test's writes.
func closeUDPSessions() {
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		if md := c.Info().Metadata; md != nil && md.NetWork == C.UDP {
			_ = c.Close()
		}
		return true
	})
}

func TestBitTorrentUDPSessionBlockedEndToEnd(t *testing.T) {
	setupBitTorrentTunnel(t, "REJECT")

	t.Run("DHT to a node then uTP to a peer", func(t *testing.T) {
		nodeA, peerB := newE2ENode(t), newE2ENode(t)
		client := netip.MustParseAddrPort("192.168.1.10:51413")

		send(client, nodeA, e2eDHTPing)
		send(client, peerB, e2eUTPSyn)
		send(client, peerB, []byte("piece data"))

		assert.Empty(t, nodeA.received())
		assert.Empty(t, peerB.received())
	})

	// The case a rule matched on the first packet alone gets wrong: the session
	// starts with something the sniffer does not recognise, so the session
	// rule is MATCH,DIRECT, and only a later destination shows BitTorrent.
	t.Run("unrecognised first packet then uTP to a peer", func(t *testing.T) {
		nodeA, peerB := newE2ENode(t), newE2ENode(t)
		client := netip.MustParseAddrPort("192.168.1.10:51414")

		send(client, nodeA, []byte("stun-ish first packet"))
		send(client, peerB, e2eUTPSyn)
		send(client, peerB, []byte("piece data"))
		// the session is a BitTorrent socket now, its other destinations are
		// matched again and rejected as well
		send(client, nodeA, []byte("second packet to A"))

		assert.Equal(t, [][]byte{[]byte("stun-ish first packet")}, nodeA.received())
		assert.Empty(t, peerB.received())
	})

	t.Run("other sessions are left alone", func(t *testing.T) {
		nodeA, peerB := newE2ENode(t), newE2ENode(t)
		client := netip.MustParseAddrPort("192.168.1.10:40000")

		send(client, nodeA, []byte("one"))
		send(client, peerB, []byte("two"))
		send(client, nodeA, []byte("three"))

		assert.Equal(t, [][]byte{[]byte("one"), []byte("three")}, nodeA.received())
		assert.Equal(t, [][]byte{[]byte("two")}, peerB.received())
	})
}

// With a non-REJECT target nothing is dropped: the session cannot be moved to
// another outbound, and the tag alone must not change how packets flow.
func TestBitTorrentUDPSessionNotRejectedEndToEnd(t *testing.T) {
	setupBitTorrentTunnel(t, "DIRECT")

	nodeA, peerB := newE2ENode(t), newE2ENode(t)
	client := netip.MustParseAddrPort("192.168.1.10:51415")

	send(client, nodeA, e2eDHTPing)
	send(client, peerB, e2eUTPSyn)
	send(client, peerB, []byte("piece data"))

	assert.Equal(t, [][]byte{e2eDHTPing}, nodeA.received())
	assert.Equal(t, [][]byte{e2eUTPSyn, []byte("piece data")}, peerB.received())
}
