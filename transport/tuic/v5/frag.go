package v5

import (
	"bytes"
	"sync"

	"github.com/metacubex/mihomo/common/lru"

	"github.com/metacubex/quic-go"
)

// MaxFragSize is a safe udp relay packet size
// because tuicv5 support udp fragment so we unneeded to do a magic modify for quic-go to increase MaxDatagramFrameSize
// it may not work fine in some platform
// "1200" from quic-go's MaxDatagramSize
// "-3" from quic-go's DatagramFrame.MaxDataLen
var MaxFragSize = 1200 - PacketOverHead - 3

func fragWriteNative(quicConn *quic.Conn, packet Packet, buf *bytes.Buffer, fragSize int) (err error) {
	fullPayload := packet.DATA
	off := 0
	fragID := uint8(0)
	fragCount := uint8((len(fullPayload) + fragSize - 1) / fragSize) // round up
	packet.FRAG_TOTAL = fragCount
	for off < len(fullPayload) {
		payloadSize := len(fullPayload) - off
		if payloadSize > fragSize {
			payloadSize = fragSize
		}
		frag := packet
		frag.FRAG_ID = fragID
		frag.SIZE = uint16(payloadSize)
		frag.DATA = fullPayload[off : off+payloadSize]
		off += payloadSize
		fragID++
		buf.Reset()
		err = frag.WriteTo(buf)
		if err != nil {
			return
		}
		data := buf.Bytes()
		err = quicConn.SendDatagram(data)
		if err != nil {
			return
		}
		packet.ADDR.TYPE = AtypNone // avoid "fragment 2/2: address in non-first fragment"
	}
	return
}

// Reassembly limits. A UDP payload never exceeds 65535 bytes, so a packet
// whose fragments add up to more is bogus. Incomplete packets age out after
// fragAge seconds; the size caps make a peer that keeps sending first
// fragments with fresh PKT_IDs evict its own oldest (usually lost) packets
// instead of growing the cache.
const (
	fragAge             = 10
	maxFragPayloadBytes = 65535
	// clientMaxFragPackets bounds incomplete packets per association on the
	// client (its cache is per association).
	clientMaxFragPackets = 64
	// serverMaxFragPackets bounds incomplete packets per QUIC connection on
	// the server (one cache shared by every association of the connection),
	// so the worst case is serverMaxFragPackets * maxFragPayloadBytes = 16 MiB
	// per connection, and a few hundred KiB in practice.
	serverMaxFragPackets = 256
)

// fragCache reassembles fragmented packets, keyed by K.
type fragCache[K comparable] struct {
	maxPackets int // 0 means clientMaxFragPackets
	lru        *lru.LruCache[K, *packetBag]
	once       sync.Once
}

// deFragger is the per-association cache of the client, keyed by PKT_ID.
type deFragger = fragCache[uint16]

type packetBag struct {
	frags []*Packet
	count uint8
	size  int
	mutex sync.Mutex
}

func newPacketBag() *packetBag {
	return new(packetBag)
}

func (d *fragCache[K]) init() {
	if d.lru == nil {
		maxPackets := d.maxPackets
		if maxPackets <= 0 {
			maxPackets = clientMaxFragPackets
		}
		d.lru = lru.New(
			lru.WithAge[K, *packetBag](fragAge),
			lru.WithUpdateAgeOnGet[K, *packetBag](),
			lru.WithSize[K, *packetBag](maxPackets),
		)
	}
}

func (d *fragCache[K]) feed(key K, m *Packet) *Packet {
	if m.FRAG_TOTAL <= 1 {
		return m
	}
	if m.FRAG_ID >= m.FRAG_TOTAL {
		// wtf is this?
		return nil
	}
	if len(m.DATA) > maxFragPayloadBytes {
		return nil
	}
	d.once.Do(d.init) // lazy init
	bag, _ := d.lru.GetOrStore(key, newPacketBag)
	bag.mutex.Lock()
	defer bag.mutex.Unlock()
	if int(m.FRAG_TOTAL) != len(bag.frags) {
		// new message, clear previous state
		bag.frags = make([]*Packet, m.FRAG_TOTAL)
		bag.count = 1
		bag.size = len(m.DATA)
		bag.frags[m.FRAG_ID] = m
		return nil
	}
	if bag.frags[m.FRAG_ID] != nil {
		return nil
	}
	if bag.size+len(m.DATA) > maxFragPayloadBytes {
		// more than a UDP packet can carry: drop the whole packet
		bag.frags = nil
		d.lru.Delete(key)
		return nil
	}
	bag.frags[m.FRAG_ID] = m
	bag.count++
	bag.size += len(m.DATA)
	if int(bag.count) != len(bag.frags) {
		return nil
	}

	// all fragments received, assemble
	data := make([]byte, 0, bag.size)
	for _, frag := range bag.frags {
		data = append(data, frag.DATA...)
	}
	p := *bag.frags[0] // recover from first fragment
	p.SIZE = uint16(len(data))
	p.DATA = data
	p.FRAG_ID = 0
	p.FRAG_TOTAL = 1
	bag.frags = nil
	d.lru.Delete(key)
	return &p
}
