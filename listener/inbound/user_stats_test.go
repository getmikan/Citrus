package inbound_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startSizedServer serves connections that send an 8-byte request
// (upload size, download size), then the upload bytes, and get the download
// bytes back.
func startSizedServer(t *testing.T) netip.AddrPort {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var hdr [8]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				up, down := binary.BigEndian.Uint32(hdr[:4]), binary.BigEndian.Uint32(hdr[4:])
				if _, err := io.CopyN(io.Discard, c, int64(up)); err != nil {
					return
				}
				_, _ = c.Write(make([]byte, down))
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

// transfer opens a connection through out and moves up bytes (plus the
// 8-byte request) up and down bytes down.
func transfer(t *testing.T, out C.ProxyAdapter, server netip.AddrPort, up, down int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, &C.Metadata{
		NetWork: C.TCP,
		DstIP:   server.Addr(),
		DstPort: server.Port(),
	})
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(up))
	binary.BigEndian.PutUint32(hdr[4:], uint32(down))
	_, err = conn.Write(append(hdr[:], make([]byte, up)...))
	require.NoError(t, err)
	n, err := io.CopyN(io.Discard, conn, int64(down))
	require.NoError(t, err)
	require.Equal(t, int64(down), n)
}

// TestInboundUserStats runs traffic of two VLESS users through the real
// tunnel (DIRECT) and checks that the per-user counters hold exactly the
// payload bytes of each user: the request and response bodies, without the
// VLESS, mux or TCP overhead. A sing-mux sub-stream is attributed to the user
// of the VLESS connection that carries it.
func TestInboundUserStats(t *testing.T) {
	tunnel.UpdateProxies(map[string]C.Proxy{"DIRECT": adapter.NewProxy(outbound.NewDirect())}, nil)
	tunnel.OnRunning()

	inboundName := "vless-user-stats-" + utils.NewUUIDV4().String()
	aliceUUID, bobUUID := utils.NewUUIDV4().String(), utils.NewUUIDV4().String()
	in, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption: inbound.BaseOption{NameStr: inboundName, Listen: "127.0.0.1", Port: "0"},
		Users: []inbound.VlessUser{
			{Username: "alice", UUID: aliceUUID},
			{Username: "bob", UUID: bobUUID},
		},
		AllowInsecure: true, // plain VLESS over loopback
	})
	require.NoError(t, err)
	require.NoError(t, in.Listen(tunnel.Tunnel))
	defer in.Close()
	assert.ElementsMatch(t, []string{"alice", "bob"}, in.InboundUsers())

	addrPort, err := netip.ParseAddrPort(in.Address())
	require.NoError(t, err)
	newOut := func(name, uuid string) *outbound.Vless {
		out, err := outbound.NewVless(outbound.VlessOption{
			BasicOption: outbound.BasicOption{},
			Name:        name,
			Server:      addrPort.Addr().String(),
			Port:        int(addrPort.Port()),
			UUID:        uuid,
		})
		require.NoError(t, err)
		return out
	}
	alice := newOut("alice", aliceUUID)
	defer alice.Close()
	bob := newOut("bob", bobUUID)
	defer bob.Close()

	server := startSizedServer(t)
	const hdr = 8

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); transfer(t, alice, server, 100_000, 1_000_000) }()
		go func() { defer wg.Done(); transfer(t, bob, server, 50_000, 20_000) }()
	}
	wg.Wait()

	// bob also opens two streams over one sing-mux connection
	mux, err := outbound.NewSingMux(outbound.SingMuxOption{Enabled: true, Protocol: "h2mux", MaxStreams: 4}, bob)
	require.NoError(t, err)
	transfer(t, mux, server, 7_000, 9_000)
	transfer(t, mux, server, 3_000, 1_000)
	_ = mux.Close()

	want := map[string][2]int64{
		"alice": {3 * (100_000 + hdr), 3 * 1_000_000},
		"bob":   {3*(50_000+hdr) + (7_000 + hdr) + (3_000 + hdr), 3*20_000 + 9_000 + 1_000},
	}
	users := statistic.DefaultManager.Users()
	for user, w := range want {
		key := statistic.UserKey{Inbound: inboundName, User: user}
		// the tunnel closes its side of a connection asynchronously
		assert.Eventually(t, func() bool {
			s, ok := users.Get(key)
			return ok && s.Conns == 0 && s.Up == w[0] && s.Down == w[1]
		}, 10*time.Second, 20*time.Millisecond, "user %s", user)
		s, _ := users.Get(key)
		assert.Equal(t, w[0], s.Up, "%s up", user)
		assert.Equal(t, w[1], s.Down, "%s down", user)
		require.Len(t, s.IPs, 1, "%s ips", user)
		assert.Equal(t, netip.MustParseAddr("127.0.0.1"), s.IPs[0].IP)
	}

	// a drain hands the bytes out once
	d := users.DrainFunc(func(k statistic.UserKey) bool { return k.Inbound == inboundName })
	require.Len(t, d, 2)
	assert.Equal(t, want["alice"][1], d[0].Down)
	d = users.DrainFunc(func(k statistic.UserKey) bool { return k.Inbound == inboundName })
	assert.Equal(t, int64(0), d[0].Up+d[0].Down+d[1].Up+d[1].Down)
}
