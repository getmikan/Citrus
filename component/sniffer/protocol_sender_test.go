package sniffer

import (
	"bytes"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	snifferTypes "github.com/metacubex/mihomo/constant/sniffer"

	"github.com/stretchr/testify/assert"
)

// recordSender records the destination of every packet the wrapper forwards
type recordSender struct {
	C.PacketSender
	forwarded []string
}

func (r *recordSender) Send(packet C.PacketAdapter) {
	r.forwarded = append(r.forwarded, packet.Metadata().RemoteAddress())
	packet.Drop()
}

// recordVerdict rejects the destinations it is told to and remembers what it
// was asked about
type recordVerdict struct {
	reject map[string]bool
	asked  []string
}

func (v *recordVerdict) verdict(metadata *C.Metadata) bool {
	if metadata.SniffProtocol != C.ProtocolBitTorrent {
		panic("verdict asked about an untagged packet")
	}
	v.asked = append(v.asked, metadata.RemoteAddress())
	return v.reject == nil || v.reject[metadata.RemoteAddress()]
}

var (
	sessionSrc  = netip.MustParseAddr("192.168.1.10")
	plainUDP    = []byte("some application payload that is not BitTorrent at all")
	dhtPingData = []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe")
)

func udpTo(dst string, data []byte) C.PacketAdapter {
	addrPort := netip.MustParseAddrPort(dst)
	metadata := &C.Metadata{NetWork: C.UDP, SrcIP: sessionSrc, SrcPort: 51413, DstIP: addrPort.Addr(), DstPort: addrPort.Port()}
	return C.NewPacketAdapter(&fakeUDPPacket{data: bytes.Clone(data), data2: bytes.Clone(data)}, metadata)
}

// startSession runs UDPSniff on the first packet like the tunnel does, then
// hands it to the returned sender
func startSession(t *testing.T, sd *Dispatcher, first C.PacketAdapter, verdict PacketVerdict) (C.PacketSender, *recordSender) {
	t.Helper()
	inner := &recordSender{}
	sender := sd.UDPSniff(first, inner, verdict)
	sender.Send(first)
	return sender, inner
}

func TestProtocolSenderTagsSessionLater(t *testing.T) {
	sd := newBitTorrentDispatcher(t)
	v := &recordVerdict{}

	// the first packet is not recognised, the session rule lets it through
	first := udpTo("198.51.100.1:3478", plainUDP)
	sender, inner := startSession(t, sd, first, v.verdict)
	assert.Empty(t, first.Metadata().SniffProtocol)

	sender.Send(udpTo("198.51.100.2:6881", plainUDP))
	// a uTP SYN to a new peer tags the session and is rejected
	sender.Send(udpTo("198.51.100.3:6881", gatingSyn))
	sender.Send(udpTo("198.51.100.3:6881", plainUDP))
	// earlier destinations of the now tagged session are matched again
	sender.Send(udpTo("198.51.100.1:3478", plainUDP))
	sender.Send(udpTo("198.51.100.2:6881", plainUDP))
	// as is any new one, whatever its packets look like
	sender.Send(udpTo("198.51.100.4:6881", plainUDP))

	assert.Equal(t, []string{"198.51.100.1:3478", "198.51.100.2:6881"}, inner.forwarded)
	// one verdict per destination, not per packet
	assert.Equal(t, []string{"198.51.100.3:6881", "198.51.100.1:3478", "198.51.100.2:6881", "198.51.100.4:6881"}, v.asked)
}

func TestProtocolSenderOnlyDropsRejected(t *testing.T) {
	sd := newBitTorrentDispatcher(t)
	// the rules send only one destination to REJECT, PROTOCOL,bittorrent
	// behind an IP rule for instance
	v := &recordVerdict{reject: map[string]bool{"198.51.100.3:6881": true}}

	sender, inner := startSession(t, sd, udpTo("198.51.100.1:6881", plainUDP), v.verdict)
	sender.Send(udpTo("198.51.100.2:6881", dhtPingData))
	sender.Send(udpTo("198.51.100.3:6881", plainUDP))
	sender.Send(udpTo("198.51.100.2:6881", plainUDP))

	assert.Equal(t, []string{"198.51.100.1:6881", "198.51.100.2:6881", "198.51.100.2:6881"}, inner.forwarded)
}

func TestProtocolSenderTaggedFromFirstPacket(t *testing.T) {
	sd := newBitTorrentDispatcher(t)
	v := &recordVerdict{}

	// the session's own rule already decided for the first destination
	first := udpTo("198.51.100.1:6881", dhtPingData)
	sender, inner := startSession(t, sd, first, v.verdict)
	assert.Equal(t, C.ProtocolBitTorrent, first.Metadata().SniffProtocol)
	sender.Send(udpTo("198.51.100.1:6881", plainUDP))
	sender.Send(udpTo("198.51.100.2:6881", plainUDP))

	assert.Equal(t, []string{"198.51.100.1:6881", "198.51.100.1:6881"}, inner.forwarded)
	assert.Equal(t, []string{"198.51.100.2:6881"}, v.asked)
}

// Only the first packets to a destination are inspected, the session is not
// sniffed forever
func TestProtocolSenderInspectionLimit(t *testing.T) {
	sd := newBitTorrentDispatcher(t)
	v := &recordVerdict{}

	sender, inner := startSession(t, sd, udpTo("198.51.100.1:6881", plainUDP), v.verdict)
	for i := 1; i < udpProtocolSniffPackets; i++ {
		sender.Send(udpTo("198.51.100.1:6881", plainUDP))
	}
	sender.Send(udpTo("198.51.100.1:6881", gatingSyn))

	assert.Len(t, inner.forwarded, udpProtocolSniffPackets+1)
	assert.Empty(t, v.asked)

	// a new destination still gets its own budget
	sender.Send(udpTo("198.51.100.2:6881", gatingSyn))
	assert.Len(t, inner.forwarded, udpProtocolSniffPackets+1)
}

func TestProtocolSenderHonoursSkipAddress(t *testing.T) {
	sd, err := NewDispatcher(&Config{
		Enable:         true,
		SkipSrcAddress: []C.IpMatcher{ipMatcher(t, "192.168.1.99/32")},
		SkipDstAddress: []C.IpMatcher{ipMatcher(t, "203.0.113.0/24")},
		Sniffers: map[snifferTypes.Type]SnifferConfig{
			snifferTypes.BitTorrent: {},
		},
	})
	assert.NoError(t, err)
	v := &recordVerdict{}

	sender, inner := startSession(t, sd, udpTo("198.51.100.1:6881", plainUDP), v.verdict)
	// a skipped destination is neither inspected nor dropped
	sender.Send(udpTo("203.0.113.5:6881", gatingSyn))
	sender.Send(udpTo("198.51.100.2:6881", gatingSyn))
	sender.Send(udpTo("203.0.113.5:6881", plainUDP))
	assert.Equal(t, []string{"198.51.100.1:6881", "203.0.113.5:6881", "203.0.113.5:6881"}, inner.forwarded)

	// a skipped source is not wrapped at all
	first := udpTo("198.51.100.1:6881", plainUDP)
	first.Metadata().SrcIP = netip.MustParseAddr("192.168.1.99")
	plain := &recordSender{}
	assert.Same(t, plain, sd.UDPSniff(first, plain, v.verdict).(*recordSender))
}

func TestProtocolSenderNeedsVerdictAndUDPSniffer(t *testing.T) {
	sd := newBitTorrentDispatcher(t)
	plain := &recordSender{}
	assert.Same(t, plain, sd.UDPSniff(udpTo("198.51.100.1:6881", plainUDP), plain, nil).(*recordSender))

	tcpOnly, err := NewDispatcher(&Config{
		Enable: true,
		Sniffers: map[snifferTypes.Type]SnifferConfig{
			snifferTypes.HTTP: {},
		},
	})
	assert.NoError(t, err)
	v := &recordVerdict{}
	assert.Same(t, plain, tcpOnly.UDPSniff(udpTo("198.51.100.1:6881", plainUDP), plain, v.verdict).(*recordSender))
}

// A rejected session is torn down and the next packet from the same socket
// opens a new one. It has to start out tagged, or the untagged rest of the
// exchange would be matched without the protocol.
func TestNewSessionInheritsSocketTag(t *testing.T) {
	sd := newBitTorrentDispatcher(t)
	v := &recordVerdict{}

	// tagged on its first packet
	startSession(t, sd, udpTo("198.51.100.1:6881", dhtPingData), v.verdict)

	next := udpTo("198.51.100.2:6881", plainUDP)
	startSession(t, sd, next, v.verdict)
	assert.Equal(t, C.ProtocolBitTorrent, next.Metadata().SniffProtocol)

	// another socket of the same host is a different application
	other := udpTo("198.51.100.2:6881", plainUDP)
	other.Metadata().SrcPort = 51414
	startSession(t, sd, other, v.verdict)
	assert.Empty(t, other.Metadata().SniffProtocol)

	// tagged later by the wrapper, remembered just the same
	fresh := udpTo("198.51.100.2:6881", plainUDP)
	fresh.Metadata().SrcPort = 51414
	sender, _ := startSession(t, sd, fresh, v.verdict)
	synPacket := udpTo("198.51.100.3:6881", gatingSyn)
	synPacket.Metadata().SrcPort = 51414
	sender.Send(synPacket)
	again := udpTo("198.51.100.4:6881", plainUDP)
	again.Metadata().SrcPort = 51414
	startSession(t, sd, again, v.verdict)
	assert.Equal(t, C.ProtocolBitTorrent, again.Metadata().SniffProtocol)
}
