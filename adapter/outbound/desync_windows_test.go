//go:build windows

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

// The native fake through the outbound's own dial. On loopback a low TTL
// never expires, so the fake prefix reaches the server: the payload is set
// to the real fragmented bytes, which keeps the stream verifiable, as the
// library's own Windows tests do.
func TestDesyncWindowsFakeThroughOutbound(t *testing.T) {
	record := captureClientHello(t)
	want := expectedFragments(t, record)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, len(want))
		_, _ = io.ReadFull(c, buf)
		got <- buf
	}()

	d := newTestDesync(t, DesyncOption{TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4, Prefix: -1, Timeout: 3000}})
	opts := d.tcp
	fake := *opts.Fake
	fake.Payload = want
	opts.Fake = &fake
	d.strategy = staticDesyncStrategy{opts}

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

// The UDP burst through ListenPacketContext: repeats fake datagrams, then the
// unchanged original, and nothing in the packet path reaches the socket.
func TestDesyncWindowsUDPBurst(t *testing.T) {
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
				Counters desync.UDPSnapshot `json:"counters"`
			} `json:"udp"`
		} `json:"desync"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	assert.Equal(t, 4, v.Desync.UDP.TTL)
	assert.Equal(t, 2, v.Desync.UDP.Repeats)
	assert.Equal(t, 1, v.Desync.UDP.Packets)
	assert.Equal(t, desync.UDPSnapshot{Packets: 2, FakePackets: 2, Peers: 1}, v.Desync.UDP.Counters)
}

// The egress guard sits outside the UDP wrapper: a server inbound user's
// datagram to a blocked address is dropped before the burst, so neither the
// fake datagrams nor the original reach it.
func TestDesyncWindowsUDPEgressGuard(t *testing.T) {
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
