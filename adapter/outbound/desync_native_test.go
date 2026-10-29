package outbound

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/egress"
	C "github.com/metacubex/mihomo/constant"

	"github.com/Nemu-x/desync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The native fakes and the UDP burst run where the library implements them
// (fake: Windows, Linux, Android; udp: also macOS) and are skipped elsewhere.

func requireFake(t *testing.T) {
	t.Helper()
	if !desync.SupportsFake() {
		t.Skip("no TCP fake on this OS")
	}
}

func requireUDPFake(t *testing.T) {
	t.Helper()
	if !desync.SupportsUDPFake() {
		t.Skip("no UDP fake on this OS")
	}
}

// withVerifiableFake makes the fake piece carry the bytes it replaces. On
// loopback a low TTL never expires, so the first transmission reaches the
// server: with the real bytes as the decoy the stream stays verifiable, as
// in the library's own tests. offset is where the fake piece starts.
func withVerifiableFake(d *Desync, wire []byte, offset int) {
	opts := d.tcp
	fake := *opts.Fake
	fake.Payload, fake.Offset = wire, offset
	opts.Fake = &fake
	d.strategy = staticDesyncStrategy{opts}
}

// readFirst reads n bytes from the first connection accepted by ln.
func readFirst(ln net.Listener, n int) <-chan []byte {
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, n)
		k, _ := io.ReadFull(c, buf)
		got <- buf[:k]
	}()
	return got
}

// The native fake through the outbound's own dial.
func TestDesyncFakeThroughOutbound(t *testing.T) {
	requireFake(t)
	record := captureClientHello(t)
	want := expectedFragments(t, record)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	got := readFirst(ln, len(want))

	d := newTestDesync(t, DesyncOption{TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4, Prefix: -1, Timeout: 3000}})
	withVerifiableFake(d, want, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, desyncMetadata(ln.Addr()))
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(record)
	require.NoError(t, err)
	assert.Equal(t, want, <-got)
}

// The fake as one of several split pieces, after a disorder or out-of-band
// first piece: the stream the server reads is the original, and the API
// reports the TTL the fake was sent with (the fallback where auto-ttl
// cannot observe the path, as on IPv4 loopback).
func TestDesyncFakeWithSplitMethods(t *testing.T) {
	requireFake(t)
	const cut = 40
	for name, option := range map[string]DesyncOption{
		"split":    {Split: "40"},
		"disorder": {Split: "40", Disorder: true},
		"oob":      {Split: "40", OOB: true, OOBByte: "z"},
		"auto-ttl": {Split: "40", Disorder: true, Fake: &DesyncFakeOption{TTL: 5, AutoTTL: &DesyncAutoTTLOption{}}},
	} {
		t.Run(name, func(t *testing.T) {
			if option.Fake == nil {
				option.Fake = &DesyncFakeOption{TTL: 5}
			}
			record := captureClientHello(t)
			tail := []byte("after the hello")
			input := append(append([]byte(nil), record...), tail...)

			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()
			got := readFirst(ln, len(input))

			d := newTestDesync(t, option)
			withVerifiableFake(d, record, cut)
			conn, err := d.DialContext(context.Background(), desyncMetadata(ln.Addr()))
			require.NoError(t, err)
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Write(input)
			require.NoError(t, err)
			assert.Equal(t, input, <-got, "the server must read the original stream")

			var v struct {
				Desync struct {
					TCP struct {
						Fake struct {
							LastTTL *struct {
								TTL  int  `json:"ttl"`
								Auto bool `json:"auto"`
							} `json:"last-ttl"`
						} `json:"fake"`
					} `json:"tcp"`
				} `json:"desync"`
			}
			raw, err := d.MarshalJSON()
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(raw, &v))
			require.NotNil(t, v.Desync.TCP.Fake.LastTTL, "the fake was sent: %s", raw)
			assert.Equal(t, 5, v.Desync.TCP.Fake.LastTTL.TTL)
			assert.False(t, v.Desync.TCP.Fake.LastTTL.Auto, "IPv4 loopback is not observed")
		})
	}
}

// The UDP burst through ListenPacketContext: repeats fake datagrams, then the
// unchanged original, and nothing in the packet path reaches the socket.
func TestDesyncUDPBurst(t *testing.T) {
	requireUDPFake(t)
	d := newTestDesync(t, DesyncOption{UDP: &DesyncUDPOption{TTL: 4, Repeats: 2, Packets: 1}})
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()
	ap := server.LocalAddr().(*net.UDPAddr).AddrPort()
	pc, err := d.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP, DstIP: ap.Addr(), DstPort: ap.Port()})
	require.NoError(t, err)
	defer pc.Close()
	_, found := N.FindUpstream[*net.UDPConn](pc, nil)
	assert.False(t, found, "the packet path can reach the socket")
	_, found = N.FindUpstream[*desync.PacketConn](pc, nil)
	assert.False(t, found, "the packet path can reach the wrapper")

	for i := 0; i < 2; i++ {
		_, err = pc.WriteTo([]byte("original"), server.LocalAddr())
		require.NoError(t, err)
	}
	require.NoError(t, server.SetReadDeadline(time.Now().Add(3*time.Second)))
	for i, want := range [][]byte{make([]byte, 64), make([]byte, 64), []byte("original"), []byte("original")} {
		buf := make([]byte, 256)
		n, _, err := server.ReadFrom(buf)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(want, buf[:n]), "datagram %d: %q", i, buf[:n])
	}

	raw, err := d.MarshalJSON()
	require.NoError(t, err)
	var v struct {
		Desync struct {
			UDP struct {
				TTL      int                `json:"ttl"`
				Repeats  int                `json:"repeats"`
				Packets  int                `json:"packets"`
				Template string             `json:"template"`
				QUICOnly bool               `json:"quic-only"`
				Counters desync.UDPSnapshot `json:"counters"`
			} `json:"udp"`
		} `json:"desync"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	assert.Equal(t, 4, v.Desync.UDP.TTL)
	assert.Equal(t, 2, v.Desync.UDP.Repeats)
	assert.Equal(t, 1, v.Desync.UDP.Packets)
	assert.Equal(t, "zero", v.Desync.UDP.Template)
	assert.False(t, v.Desync.UDP.QUICOnly)
	assert.Equal(t, desync.UDPSnapshot{Packets: 2, FakePackets: 2, Peers: 1}, v.Desync.UDP.Counters)
}

// With quic-only, datagrams that are not a QUIC client Initial pass without
// a burst and do not use up packets; the Initial gets QUIC decoys.
func TestDesyncUDPQUICOnly(t *testing.T) {
	requireUDPFake(t)
	d := newTestDesync(t, DesyncOption{UDP: &DesyncUDPOption{TTL: 4, Repeats: 2, Packets: 1, Template: "quic", SNI: "www.example.com", QUICOnly: true}})
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()
	ap := server.LocalAddr().(*net.UDPAddr).AddrPort()
	pc, err := d.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP, DstIP: ap.Addr(), DstPort: ap.Port()})
	require.NoError(t, err)
	defer pc.Close()

	initial, err := desync.QUICInitialPayload(desyncTestSNI)
	require.NoError(t, err)
	for _, p := range [][]byte{[]byte("not quic"), []byte("still not quic"), initial} {
		_, err = pc.WriteTo(p, server.LocalAddr())
		require.NoError(t, err)
	}
	require.NoError(t, server.SetReadDeadline(time.Now().Add(3*time.Second)))
	var got [][]byte
	for i := 0; i < 5; i++ {
		buf := make([]byte, 2048)
		n, _, err := server.ReadFrom(buf)
		require.NoError(t, err)
		got = append(got, buf[:n])
	}
	assert.Equal(t, "not quic", string(got[0]), "no burst before a datagram that is not QUIC")
	assert.Equal(t, "still not quic", string(got[1]), "and it did not use up the packets")
	for _, fake := range got[2:4] {
		assert.Len(t, fake, 1200, "a QUIC Initial decoy")
		assert.Equal(t, byte(0xc0), fake[0]&0xf0, "long header, Initial type")
		assert.NotEqual(t, initial, fake)
	}
	assert.Equal(t, initial, got[4])
	assert.Equal(t, desync.UDPSnapshot{Packets: 3, FakePackets: 2, Peers: 1}, d.udp.Counters.Snapshot())
}

// The egress guard sits outside the UDP wrapper: a server inbound user's
// datagram to a blocked address is dropped before the burst, so neither the
// fake datagrams nor the original reach it.
func TestDesyncUDPEgressGuard(t *testing.T) {
	requireUDPFake(t)
	withEgressOptions(t, egress.Options{Enable: true})
	d := newTestDesync(t, DesyncOption{UDP: &DesyncUDPOption{TTL: 4, Repeats: 2, Packets: 1}})
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()
	ap := server.LocalAddr().(*net.UDPAddr).AddrPort()
	pc, err := d.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP, Type: C.TUIC, DstIP: ap.Addr(), DstPort: ap.Port()})
	require.NoError(t, err, "the session is opened")
	defer pc.Close()

	_, err = pc.WriteTo([]byte("original"), server.LocalAddr())
	require.NoError(t, err, "dropped like a lost datagram")
	require.NoError(t, server.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
	_, _, err = server.ReadFrom(make([]byte, 256))
	assert.Error(t, err, "nothing may reach the blocked address")
	assert.Equal(t, desync.UDPSnapshot{}, d.udp.Counters.Snapshot(), "no fake datagram was sent")
}
