package tunnel_test

import (
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	RC "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"
)

// sinkListener answers every connection like the handshake phase of
// test/bench/compare: it reads one byte, writes 64 and closes.
func sinkListener(b *testing.B) net.Listener {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	go func() {
		answer := make([]byte, 64)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				var one [1]byte
				if _, err := io.ReadFull(c, one[:]); err == nil {
					_, _ = c.Write(answer)
				}
				_ = c.Close()
			}()
		}
	}()
	return ln
}

// BenchmarkNewConn measures a new tunneled connection of an inbound user
// through the tunnel: rule match (MATCH,DIRECT), user admission, dial over
// loopback, tracker, a 1-byte request, a 64-byte answer, close. The inbound
// side is a net.Pipe, so the cost of the inbound protocol is not included.
func BenchmarkNewConn(b *testing.B) {
	ln := sinkListener(b)
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	tunnel.UpdateProxies(map[string]C.Proxy{
		"DIRECT": adapter.NewProxy(outbound.NewDirect()),
	}, nil)
	tunnel.UpdateRules([]C.Rule{RC.NewMatch("DIRECT")}, nil, nil)
	tunnel.SetMode(tunnel.Rule)
	tunnel.OnRunning()
	defer func() {
		tunnel.UpdateRules(nil, nil, nil)
		tunnel.UpdateProxies(map[string]C.Proxy{}, nil)
		tunnel.OnSuspend()
	}()

	// as on a server: info lines are not printed
	oldLevel := log.Level()
	log.SetLevel(log.WARNING)
	defer log.SetLevel(oldLevel)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		buf := make([]byte, 128)
		for pb.Next() {
			client, server := net.Pipe()
			metadata := &C.Metadata{
				NetWork: C.TCP,
				Type:    C.TROJAN,
				SrcIP:   netip.MustParseAddr("192.0.2.1"),
				SrcPort: 40000,
				DstIP:   netip.MustParseAddr("127.0.0.1"),
				DstPort: port,
				InName:  "bench-in",
				InUser:  "u",
			}
			go tunnel.Tunnel.HandleTCPConn(server, metadata)
			if _, err := client.Write([]byte{1}); err != nil {
				b.Error(err)
				return
			}
			n := 0
			for {
				m, err := client.Read(buf[n:])
				n += m
				if err != nil {
					break
				}
			}
			_ = client.Close()
			if n != 64 {
				b.Errorf("got %d bytes", n)
				return
			}
		}
	})
}
