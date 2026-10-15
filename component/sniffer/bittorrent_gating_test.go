package sniffer

import (
	"encoding/hex"
	"net"
	"net/netip"
	"testing"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/cidr"
	C "github.com/metacubex/mihomo/constant"
	snifferTypes "github.com/metacubex/mihomo/constant/sniffer"

	"github.com/stretchr/testify/assert"
)

var (
	gatingHandshake, _ = hex.DecodeString("13426974546f7272656e742070726f746f636f6c0000000000100000e21ea9569b69bab33c97851d0298bdfa89bc90922d5554313631302dea812fcd6a3563e3be40c1d1")
	gatingSyn, _       = hex.DecodeString("410277ef0b1fb1f60000000000040000c233000000080000000000000000")
)

func ipMatcher(t *testing.T, prefix string) C.IpMatcher {
	t.Helper()
	set := cidr.NewIpCidrSet()
	assert.NoError(t, set.AddIpCidrForString(prefix))
	assert.NoError(t, set.Merge())
	return set
}

func sniffTCPHandshake(t *testing.T, sd *Dispatcher, metadata *C.Metadata) bool {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = client.Write(gatingHandshake)
	}()
	return sd.TCPSniff(N.NewBufferedConn(server), metadata)
}

// Protocol sniffers never change the destination, so they must not be gated on
// parse-pure-ip and an empty Host the way domain sniffing is: a connection that
// already has a domain (fake-ip, redir-host, a SOCKS client sending names) is
// just as likely to be BitTorrent, a tracker or a web seed for instance.
func TestProtocolSniffIgnoresDomainGating(t *testing.T) {
	sd, err := NewDispatcher(&Config{
		Enable:      true,
		ParsePureIp: false,
		Sniffers: map[snifferTypes.Type]SnifferConfig{
			snifferTypes.BitTorrent: {},
		},
	})
	assert.NoError(t, err)

	tcp := &C.Metadata{NetWork: C.TCP, Host: "peer.example.com", DstIP: netip.MustParseAddr("198.51.100.7"), DstPort: 6881}
	assert.False(t, sniffTCPHandshake(t, sd, tcp))
	assert.Equal(t, C.ProtocolBitTorrent, tcp.SniffProtocol)
	assert.Equal(t, "peer.example.com", tcp.Host)

	// pure IP but parse-pure-ip off: still tagged
	pureIP := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("198.51.100.7"), DstPort: 6881}
	assert.False(t, sniffTCPHandshake(t, sd, pureIP))
	assert.Equal(t, C.ProtocolBitTorrent, pureIP.SniffProtocol)

	udp := &C.Metadata{NetWork: C.UDP, Host: "peer.example.com", DstIP: netip.MustParseAddr("198.51.100.7"), DstPort: 6881}
	sd.UDPSniff(constantPacket(gatingSyn, udp), &fakeSender{}, nil)
	assert.Equal(t, C.ProtocolBitTorrent, udp.SniffProtocol)
	assert.Equal(t, "peer.example.com", udp.Host)
}

// skip-src-address and skip-dst-address exempt a connection from every sniffer
func TestProtocolSniffHonoursSkipAddress(t *testing.T) {
	sd, err := NewDispatcher(&Config{
		Enable:         true,
		ParsePureIp:    true,
		SkipSrcAddress: []C.IpMatcher{ipMatcher(t, "192.168.0.3/32")},
		SkipDstAddress: []C.IpMatcher{ipMatcher(t, "203.0.113.0/24")},
		Sniffers: map[snifferTypes.Type]SnifferConfig{
			snifferTypes.BitTorrent: {},
		},
	})
	assert.NoError(t, err)

	for name, metadata := range map[string]func(network C.NetWork) *C.Metadata{
		"skipped source": func(network C.NetWork) *C.Metadata {
			return &C.Metadata{NetWork: network, SrcIP: netip.MustParseAddr("192.168.0.3"), DstIP: netip.MustParseAddr("198.51.100.7"), DstPort: 6881}
		},
		"skipped destination": func(network C.NetWork) *C.Metadata {
			return &C.Metadata{NetWork: network, SrcIP: netip.MustParseAddr("192.168.0.4"), DstIP: netip.MustParseAddr("203.0.113.9"), DstPort: 6881}
		},
	} {
		tcp := metadata(C.TCP)
		assert.False(t, sniffTCPHandshake(t, sd, tcp))
		assert.Empty(t, tcp.SniffProtocol, name)

		udp := metadata(C.UDP)
		sd.UDPSniff(constantPacket(gatingSyn, udp), &fakeSender{}, nil)
		assert.Empty(t, udp.SniffProtocol, name)
	}

	// and an address in neither list is still sniffed
	tcp := &C.Metadata{NetWork: C.TCP, SrcIP: netip.MustParseAddr("192.168.0.4"), DstIP: netip.MustParseAddr("198.51.100.7"), DstPort: 6881}
	assert.False(t, sniffTCPHandshake(t, sd, tcp))
	assert.Equal(t, C.ProtocolBitTorrent, tcp.SniffProtocol)
}

// A domain sniffer and the protocol sniffer on the same port both get their turn
func TestProtocolSniffAlongsideDomainSniff(t *testing.T) {
	sd, err := NewDispatcher(&Config{
		Enable:      true,
		ParsePureIp: true,
		Sniffers: map[snifferTypes.Type]SnifferConfig{
			snifferTypes.HTTP:       {Ports: nil},
			snifferTypes.BitTorrent: {},
		},
	})
	assert.NoError(t, err)

	// BitTorrent on the HTTP port: no domain, but tagged
	metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("198.51.100.7"), DstPort: 80}
	assert.False(t, sniffTCPHandshake(t, sd, metadata))
	assert.Equal(t, C.ProtocolBitTorrent, metadata.SniffProtocol)

	// HTTP on the HTTP port: a domain, no tag
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()
	metadata = &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("198.51.100.8"), DstPort: 80}
	assert.True(t, sd.TCPSniff(N.NewBufferedConn(server), metadata))
	assert.Equal(t, "example.com", metadata.SniffHost)
	assert.Empty(t, metadata.SniffProtocol)
}
