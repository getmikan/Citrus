package v5

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func fragTestPacket(pktID uint16, total, id uint8, data []byte) *Packet {
	addr := NewAddressAddrPort(netip.MustParseAddrPort("127.0.0.1:53"))
	if id != 0 {
		addr = Address{TYPE: AtypNone}
	}
	p := NewPacket(1, pktID, total, id, uint16(len(data)), addr, data)
	return &p
}

func TestFragCacheReassembles(t *testing.T) {
	var d deFragger
	require.Nil(t, d.feed(7, fragTestPacket(7, 3, 2, []byte("cc"))))
	require.Nil(t, d.feed(7, fragTestPacket(7, 3, 0, []byte("aa"))))
	require.Nil(t, d.feed(7, fragTestPacket(7, 3, 0, []byte("aa")))) // duplicate
	p := d.feed(7, fragTestPacket(7, 3, 1, []byte("bb")))
	require.NotNil(t, p)
	require.Equal(t, []byte("aabbcc"), p.DATA)
	require.EqualValues(t, 6, p.SIZE)
	require.EqualValues(t, 1, p.FRAG_TOTAL)
}

// A peer that keeps sending first fragments under fresh packet IDs evicts its
// own oldest incomplete packets instead of growing the cache without bound.
func TestFragCacheBoundsIncompletePackets(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cache *fragCache[uint32]
		limit int
	}{
		{"client", &fragCache[uint32]{}, clientMaxFragPackets},
		{"server", &fragCache[uint32]{maxPackets: serverMaxFragPackets}, serverMaxFragPackets},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const packets = 4096
			for i := uint32(0); i < packets; i++ {
				require.Nil(t, tc.cache.feed(i, fragTestPacket(uint16(i), 2, 0, []byte("a"))))
			}
			// the most recent ones still reassemble
			for i := uint32(packets - tc.limit); i < packets; i++ {
				p := tc.cache.feed(i, fragTestPacket(uint16(i), 2, 1, []byte("b")))
				require.NotNil(t, p, "packet %d", i)
				require.Equal(t, []byte("ab"), p.DATA)
			}
			// the older ones are gone: their second fragment completes nothing
			require.Nil(t, tc.cache.feed(0, fragTestPacket(0, 2, 1, []byte("b"))))
			require.Nil(t, tc.cache.feed(packets-uint32(tc.limit)-1, fragTestPacket(0, 2, 1, []byte("b"))))
		})
	}
}

// Fragments adding up to more than a UDP packet can carry are dropped.
func TestFragCacheBoundsPacketSize(t *testing.T) {
	var d deFragger
	chunk := bytes.Repeat([]byte{1}, 30000)
	require.Nil(t, d.feed(1, fragTestPacket(1, 3, 0, chunk)))
	require.Nil(t, d.feed(1, fragTestPacket(1, 3, 1, chunk)))
	require.Nil(t, d.feed(1, fragTestPacket(1, 3, 2, chunk))) // 90000 bytes: dropped
	// the bag is gone, a retransmitted last fragment completes nothing
	require.Nil(t, d.feed(1, fragTestPacket(1, 3, 2, []byte("x"))))

	// a full-size UDP payload still fits
	part := bytes.Repeat([]byte{2}, maxFragPayloadBytes/3)
	require.Nil(t, d.feed(2, fragTestPacket(2, 3, 0, part)))
	require.Nil(t, d.feed(2, fragTestPacket(2, 3, 1, part)))
	p := d.feed(2, fragTestPacket(2, 3, 2, part))
	require.NotNil(t, p)
	require.Len(t, p.DATA, 3*len(part))
}

// The server reassembles in one cache per connection, so the incomplete
// packets of all associations of a connection share one bound.
func TestServerFragCacheIsPerConnection(t *testing.T) {
	h := NewServerHandler(&ServerOption{}, nil, [16]byte{}).(*serverHandler)
	require.Equal(t, serverMaxFragPackets, h.fragCache.maxPackets)
}
