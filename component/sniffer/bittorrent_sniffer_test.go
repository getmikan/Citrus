package sniffer

// The packet samples below are taken from
// https://github.com/SagerNet/sing-box/blob/f2bbf6b2aaafd10ab7a6ca52e790732a4bcf447f/common/sniff/bittorrent_test.go
// which is licensed under the GNU General Public License v3.0 or later, with an
// additional term declining to grant the right to use the name of that project
// or to imply association with it.
// Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

import (
	"encoding/hex"
	"errors"
	"math/rand"
	"strconv"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
)

func TestSniffBitTorrentHandshake(t *testing.T) {
	packets := []string{
		"13426974546f7272656e742070726f746f636f6c0000000000100000e21ea9569b69bab33c97851d0298bdfa89bc90922d5554313631302dea812fcd6a3563e3be40c1d1",
		"13426974546f7272656e742070726f746f636f6c00000000001000052aa4f5a7e209e54b32803d43670971c4c8caaa052d5452333030302d653369733079647675763638",
		"13426974546f7272656e742070726f746f636f6c00000000001000052aa4f5a7e209e54b32803d43670971c4c8caaa052d5452343035302d6f7a316c6e79377931716130",
	}

	bt, err := NewBitTorrentSniffer(SnifferConfig{})
	assert.NoError(t, err)

	for _, pkt := range packets {
		data, err := hex.DecodeString(pkt)
		assert.NoError(t, err)

		protocol, err := bt.SniffProtocol(C.TCP, data)
		assert.NoError(t, err)
		assert.Equal(t, C.ProtocolBitTorrent, protocol)
	}
}

func TestSniffIncompleteBitTorrentHandshake(t *testing.T) {
	data, err := hex.DecodeString("13426974546f7272656e74")
	assert.NoError(t, err)

	// a truncated but still matching prefix must ask for more data instead of
	// being rejected, otherwise the dispatcher gives up before the rest arrives
	var need *errNeedAtLeastData
	err = SniffBitTorrentHandshake(data)
	assert.True(t, errors.As(err, &need))
	assert.Equal(t, len(btHandshakeHeader), need.length)
}

func TestSniffNotBitTorrentHandshake(t *testing.T) {
	data, err := hex.DecodeString("13426974546f7272656e75")
	assert.NoError(t, err)

	var need *errNeedAtLeastData
	err = SniffBitTorrentHandshake(data)
	assert.Error(t, err)
	assert.False(t, errors.As(err, &need))
}

func TestSniffUTP(t *testing.T) {
	packets := []string{
		// ST_SYN with the extension bits extension, as libutp sends it
		"410277ef0b1fb1f60000000000040000c233000000080000000000000000",
		// ST_SYN without extensions, as libtorrent sends it
		"4100a1b2000f4240000000000010000012340000",
	}

	bt, err := NewBitTorrentSniffer(SnifferConfig{})
	assert.NoError(t, err)

	for _, pkt := range packets {
		data, err := hex.DecodeString(pkt)
		assert.NoError(t, err)

		protocol, err := bt.SniffProtocol(C.UDP, data)
		assert.NoError(t, err)
		assert.Equal(t, C.ProtocolBitTorrent, protocol)
	}
}

// Only the packet that opens a uTP connection is recognised. Packets from the
// middle of a flow have no structure tight enough to tell them from random
// data, they are covered by the session already being tagged instead.
func TestSniffUTPMidFlow(t *testing.T) {
	packets := []string{
		// ST_DATA
		"010041a282d7ee7b583afb160004000006d8318da776968f92d666f7963f32dae23ba0d2c810d8b8209cc4939f54fde9eeaa521c2c20c9ba7f43f4fb0375f28de06643b5e3ca4685ab7ac76adca99783be72ef05ed59ef4234f5712b75b4c7c0d7bee8fe2ca20ad626ba5bb0ffcc16bf06790896f888048cf72716419a07db1a3dca4550fbcea75b53e97235168a221cf3e553dfbb723961bd719fab038d86e0ecb74747f5a2cd669de1c4b9ad375f3a492d09d98cdfad745435625401315bbba98d35d32086299801377b93495a63a9efddb8d05f5b37a5c5b1c0a25e917f12007bb5e05013ada8aff544fab8cadf61d80ddb0b60f12741e44515a109d144fd53ef845acb4b5ccf0d6fc302d7003d76df3fc3423bb0237301c9e88f900c2d392a8e0fdb36d143cf7527a93fd0a2638b746e72f6699fffcd4fd15348fce780d4caa04382fd9faf1ca0ae377ca805da7536662b84f5ee18dd3ae38fcb095a7543e55f9069ae92c8cf54ae44e97b558d35e2545c66601ed2149cbc32bd6df199a2be7cf0da8b2ff137e0d23e776bc87248425013876d3a3cc31a83b424b752bd0346437f24b532978005d8f5b1b0be1a37a2489c32a18a9ad3118e3f9d30eb299bffae18e1f0677c2a5c185e62519093fe6bc2b7339299ea50a587989f726ca6443a75dd5bb936f6367c6355d80fae53ff529d740b2e5576e3eefdf1fdbfc69c3c8d8ac750512635de63e054bee1d3b689bc1b2bc3d2601e42a00b5c89066d173d4ae7ffedfd2274e5cf6d868fbe640aedb69b8246142f00b32d459974287537ddd5373460dcbc92f5cfdd7a3ed6020822ae922d947893752ca1983d0d32977374c384ac8f5ab566859019b7351526b9f13e932037a55bb052d9deb3b3c23317e0784fdc51a64f2159bfea3b069cf5caf02ee2c3c1a6b6b427bb16165713e8802d95b5c8ed77953690e994bd38c9ae113fedaf6ee7fc2b96c032ceafc2a530ad0422e84546b9c6ad8ef6ea02fa508abddd1805c38a7b42e9b7c971b1b636865ebec06ed754bb404cd6b4e6cc8cb77bd4a0c43410d5cd5ef8fe853a66d49b3b9e06cb141236cdbfdd5761601dc54d1250b86c660e0f898fe62526fdd9acf0eab60a3bbbb2151970461f28f10b31689594bea646c4b03ee197d63bdef4e5a7c22716b3bb9494a83b78ecd81b338b80ac6c09c43485b1b09ba41c74343832c78f0520c1d659ac9eb1502094141e82fb9e5e620970ebc0655514c43c294a7714cbf9a499d277daf089f556398a01589a77494bec8bfb60a108f3813b55368672b88c1af40f6b3c8b513f7c70c3e0efce85228b8b9ec67ba0393f9f7305024d8e2da6a26cf85613d14f249170ce1000089df4c9c260df7f8292aa2ecb5d5bac97656d59aa248caedea2d198e51ce87baece338716d114b458de02d65c9ff808ca5b5b73723b4d1e962d9ac2d98176544dc9984cf8554d07820ef3dd0861cfe57b478328046380de589adad94ee44743ffac73bb7361feca5d56f07cf8ce75080e261282ae30350d7882679b15cab9e7e53ddf93310b33f7390ae5d318bb53f387e6af5d0ef4f947fc9cb8e7e38b52c7f8d772ece6156b38d88796ea19df02c53723b44df7c76315a0de9462f27287e682d2b4cda1a68fe00d7e48c51ee981be44e1ca940fb5190c12655edb4a83c3a4f33e48a015692df4f0b3d61656e362aca657b5ae8c12db5a0db3db1e45135ee918b66918f40e53c4f83e9da0cddfe63f736ae751ab3837a30ae3220d8e8e311487093a7b90c7e7e40dd54ca750e19452f9193aa892aa6a6229ab493dadae988b1724f7898ee69c36d3eb7364c4adbeca811cfe2065873e78c2b6dfdf1595f7a7831c07e03cda82e4f86f76438dfb2b07c13638ce7b509cfa71b88b5102b39a203b423202088e1c2103319cb32c13c1e546ff8612fa194c95a7808ab767c265a1bd5fa0efed5c8ec1701876a00ec8",
		"01001ecb68176f215d04326300100000dbcf30292d14b54e9ee2d115ee5b8ebc7fad3e882d4fcdd0c14c6b917c11cb4c6a9f410b52a33ae97c2ac77c7a2b122b8955e09af3c5c595f1b2e79ca57cfe44c44e069610773b9bc9ba223d7f6b383e3adddd03fb88a8476028e30979c2ef321ffc97c5c132bcf9ac5b410bbb5ec6cefca3c7209202a14c5ae922b6b157b0a80249d13ffe5b996af0bc8e54ba576d148372494303e7ead0602b05b9c8fc97d48508a028a04d63a1fd28b0edfcd5c51715f63188b53eefede98a76912dca98518551a8856567307a56a702cbfcc115ea0c755b418bc2c7b57721239b82f09fb24328a4b0ce0f109bcb2a64e04b8aadb1f8487585425acdf8fc4ec8ea93cfcec5ac098bb29d42ddef6e46b03f34a5de28316726699b7cb5195c33e5c48abe87d591d63f9991c84c30819d186d6e0e95fd83c8dff07aa669c4430989bcaccfeacb9bcadbdb4d8f1964dbeb9687745656edd30b21c66cc0a1d742a78717d134a19a7f02d285a4973b1a198c00cfdff4676608dc4f3e817e3463c3b4e2c80d3e8d4fbac541a58a2fb7ad6939f607f8144eff6c8b0adc28ee5609ea158987519892fb",
		// ST_STATE
		"21001ecb6817f2805d044fd700100000dbd03029",
	}

	for _, pkt := range packets {
		data, err := hex.DecodeString(pkt)
		assert.NoError(t, err)
		assert.Error(t, SniffUTP(data))
	}
}

func TestSniffUTPMalformedSyn(t *testing.T) {
	for name, pkt := range map[string]string{
		"payload after the header":       "4100a1b2000f4240000000000010000012340000ff",
		"zero window":                    "4100a1b2000f4240000000000000000012340000",
		"extension bits of wrong length": "410277ef0b1fb1f60000000000040000c2330000000400000000",
		"unknown extension":              "410777ef0b1fb1f60000000000040000c233000000080000000000000000",
		"truncated extension":            "410277ef0b1fb1f60000000000040000c2330000000800000000",
		"selective ack not in words":     "410177ef0b1fb1f60000000000040000c233000000030000ff",
		"version 2":                      "4200a1b2000f4240000000000010000012340000",
		"delay sample before any reply":  "4100a1b2000f4240000001000010000012340000",
	} {
		data, err := hex.DecodeString(pkt)
		assert.NoError(t, err, name)
		assert.Error(t, SniffUTP(data), name)
	}
}

// WireGuard messages: type byte, three reserved zero bytes, fixed lengths.
// A handshake initiation used to pass the uTP check as ST_DATA.
func TestSniffNotWireGuard(t *testing.T) {
	bt, err := NewBitTorrentSniffer(SnifferConfig{})
	assert.NoError(t, err)

	rnd := rand.New(rand.NewSource(1))
	for _, shape := range []struct {
		ty     byte
		length int
	}{
		{wgHandshakeInitiation, wgHandshakeInitiationSize},
		{wgHandshakeResponse, wgHandshakeResponseSize},
		{wgCookieReply, wgCookieReplySize},
		{wgTransportData, 32},
		{wgTransportData, 32 + 16*80},
	} {
		for i := 0; i < 1000; i++ {
			data := make([]byte, shape.length)
			rnd.Read(data)
			data[0], data[1], data[2], data[3] = shape.ty, 0, 0, 0
			assert.True(t, isWireGuard(data))
			_, err := bt.SniffProtocol(C.UDP, data)
			assert.Error(t, err, "WireGuard type %d, %d bytes", shape.ty, shape.length)
		}
	}

	// the shape check itself must not swallow a uTP SYN or a tracker request
	syn, _ := hex.DecodeString("4100a1b2000f4240000000000010000012340000")
	assert.False(t, isWireGuard(syn))
	tracker, _ := hex.DecodeString("00000417271019800000000078e90560")
	assert.False(t, isWireGuard(tracker))
}

// TestSniffBitTorrentRandomUDP measures the false positive rate of the UDP
// detectors on random datagrams of typical sizes. The generic uTP header check
// used to accept about 83 in a million random 64 byte datagrams.
func TestSniffBitTorrentRandomUDP(t *testing.T) {
	bt, err := NewBitTorrentSniffer(SnifferConfig{})
	assert.NoError(t, err)

	const rounds = 200000
	rnd := rand.New(rand.NewSource(2))
	for _, size := range []int{20, 30, 64, 148, 512, 1200} {
		data := make([]byte, size)
		hits := 0
		for i := 0; i < rounds; i++ {
			rnd.Read(data)
			if _, err := bt.SniffProtocol(C.UDP, data); err == nil {
				hits++
			}
		}
		t.Logf("random %d byte datagrams: %d of %d detected as BitTorrent", size, hits, rounds)
		// a 20 byte datagram matches a bare ST_SYN header with probability
		// about 2^-48 (first byte, extension byte, zero delay sample), anything
		// longer has to produce an extension chain ending exactly at its end
		assert.Zero(t, hits, "%d byte datagrams", size)
	}
}

func TestSniffUDPTracker(t *testing.T) {
	connectPackets := []string{
		"00000417271019800000000078e90560",
		"00000417271019800000000022c5d64d",
		"000004172710198000000000b3863541",
	}

	bt, err := NewBitTorrentSniffer(SnifferConfig{})
	assert.NoError(t, err)

	for _, pkt := range connectPackets {
		data, err := hex.DecodeString(pkt)
		assert.NoError(t, err)

		protocol, err := bt.SniffProtocol(C.UDP, data)
		assert.NoError(t, err)
		assert.Equal(t, C.ProtocolBitTorrent, protocol)
	}
}

func TestSniffNotUTP(t *testing.T) {
	packets := []string{
		// an SDP packet that passes the uTP header check but has a bogus extension chain
		"0102736470696e674958d580121500000000000079aaed6717a39c27b07c0c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		// a short packet cannot be a uTP header at all
		"2100",
	}

	for _, pkt := range packets {
		data, err := hex.DecodeString(pkt)
		assert.NoError(t, err)
		assert.Error(t, SniffUTP(data))
	}
}

// TCP-only and UDP-only detectors must not be applied to the wrong network,
// which is the whole reason SniffProtocol takes a network
func TestBitTorrentNetworkSeparation(t *testing.T) {
	bt, err := NewBitTorrentSniffer(SnifferConfig{})
	assert.NoError(t, err)

	handshake, err := hex.DecodeString("13426974546f7272656e742070726f746f636f6c0000000000100000e21ea9569b69bab33c97851d0298bdfa89bc90922d5554313631302dea812fcd6a3563e3be40c1d1")
	assert.NoError(t, err)
	_, err = bt.SniffProtocol(C.UDP, handshake)
	assert.Error(t, err)

	utp, err := hex.DecodeString("410277ef0b1fb1f60000000000040000c233000000080000000000000000")
	assert.NoError(t, err)
	_, err = bt.SniffProtocol(C.TCP, utp)
	assert.Error(t, err)
}

// the sniffer must land in the protocol list, not the domain one
func TestBitTorrentIsProtocolSniffer(t *testing.T) {
	bt, err := NewBitTorrentSniffer(SnifferConfig{})
	assert.NoError(t, err)

	_, err = bt.SniffData([]byte("13BitTorrent protocol"))
	assert.Error(t, err)

	// BitTorrent peers use arbitrary ports, so the default range is everything
	assert.True(t, bt.SupportPort(1))
	assert.True(t, bt.SupportPort(6881))
	assert.True(t, bt.SupportPort(65535))
}

// krpc assembles a KRPC message from already bencoded pieces
func krpc(parts ...string) []byte {
	return []byte("d" + strings.Join(parts, "") + "e")
}

func bstr(s string) string {
	return strconv.Itoa(len(s)) + ":" + s
}

// DHT messages built after the examples in BEP 5, with binary node ids and
// info hashes as real clients send them, plus the BEP 42 "ip" key and the
// client version "v" key libtorrent and others add.
func TestSniffDHT(t *testing.T) {
	nodeID := "\x8a\x1f\x00\xe3\x52\x9d\x0c\x77\x10\x2b\xfe\x01\x99\x4d\x5e\xa0\x3c\x7b\x00\x11"
	infoHash := "\xd2\x74\x8f\x9a\x0b\xc3\x1e\x55\x60\x02\xaf\x9e\x13\x37\xbe\xef\x00\x42\x8c\x01"
	peer := "\xc0\xa8\x01\x02\x1a\xe1"
	compactNode := nodeID + "\x5d\xb8\xd8\x22\x1a\xe1"
	tid := "\x9c\x01"
	version := "LT\x02\x00"

	bt, err := NewBitTorrentSniffer(SnifferConfig{})
	assert.NoError(t, err)

	for name, pkt := range map[string][]byte{
		"ping query":    krpc("1:ad2:id", bstr(nodeID), "e1:q4:ping1:t", bstr(tid), "1:y1:q"),
		"ping response": krpc("1:rd2:id", bstr(nodeID), "e1:t", bstr(tid), "1:y1:r"),
		"find_node query": krpc("1:ad2:id", bstr(nodeID), "6:target", bstr(infoHash), "e1:q9:find_node1:t", bstr(tid),
			"1:v", bstr(version), "1:y1:q"),
		"find_node response": krpc("1:rd2:id", bstr(nodeID), "5:nodes", bstr(compactNode+compactNode), "e1:t", bstr(tid), "1:y1:r"),
		"get_peers query": krpc("1:ad2:id", bstr(nodeID), "9:info_hash", bstr(infoHash), "e1:q9:get_peers1:t", bstr(tid),
			"1:v", bstr(version), "1:y1:q"),
		"get_peers response with values": krpc("1:rd2:id", bstr(nodeID), "5:token", bstr("\x01\x02\x03\x04\x05\x06\x07\x08"),
			"6:valuesl", bstr(peer), bstr(peer), "ee1:t", bstr(tid), "1:y1:r"),
		"announce_peer query": krpc("1:ad2:id", bstr(nodeID), "12:implied_porti1e9:info_hash", bstr(infoHash),
			"4:porti6881e5:token", bstr("aoeusnth"), "e1:q13:announce_peer1:t", bstr(tid), "1:y1:q"),
		"BEP 42 response": krpc("2:ip", bstr(peer), "1:rd2:id", bstr(nodeID), "e1:t", bstr(tid), "1:v", bstr(version), "1:y1:r"),
		"error":           krpc("1:eli201e", bstr("A Generic Error Ocurred"), "e1:t", bstr(tid), "1:y1:e"),
	} {
		assert.NoError(t, SniffDHT(pkt), name)
		protocol, err := bt.SniffProtocol(C.UDP, pkt)
		assert.NoError(t, err, name)
		assert.Equal(t, C.ProtocolBitTorrent, protocol, name)

		// DHT is UDP only
		_, err = bt.SniffProtocol(C.TCP, pkt)
		assert.Error(t, err, name)
	}
}

func TestSniffNotDHT(t *testing.T) {
	nodeID := strings.Repeat("\xab", 20)
	ping := krpc("1:ad2:id", bstr(nodeID), "e1:q4:ping1:t2:aa1:y1:q")

	nested := "d1:ad2:id" + bstr(nodeID) + "1:x" + strings.Repeat("l", 64) + strings.Repeat("e", 64) + "e1:q4:ping1:t2:aa1:y1:qe"

	for name, pkt := range map[string][]byte{
		"truncated":          ping[:len(ping)-1],
		"trailing data":      append(append([]byte(nil), ping...), 'e'),
		"short node id":      krpc("1:ad2:id", bstr(nodeID[:19]), "e1:q4:ping1:t2:aa1:y1:q"),
		"no node id":         krpc("1:ad6:target", bstr(nodeID), "e1:q4:ping1:t2:aa1:y1:q"),
		"query without name": krpc("1:ad2:id", bstr(nodeID), "e1:t2:aa1:y1:q"),
		"no transaction id":  krpc("1:ad2:id", bstr(nodeID), "e1:q4:ping1:y1:q"),
		"unknown type":       krpc("1:ad2:id", bstr(nodeID), "e1:q4:ping1:t2:aa1:y1:x"),
		"response as query":  krpc("1:rd2:id", bstr(nodeID), "e1:t2:aa1:y1:q"),
		"error without list": krpc("1:ei201e1:t2:aa1:y1:e"),
		"string past end":    []byte("d1:ad2:id99:abce"),
		"deep nesting":       []byte(nested),
		"json":               []byte(`{"a":{"id":"x"},"y":"q"}`),
		"plain d...e":        []byte("dns lookup for example.com failed, please retry later: code e"),
	} {
		assert.Error(t, SniffDHT(pkt), name)
	}
}
