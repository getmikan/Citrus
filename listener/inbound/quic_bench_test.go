package inbound_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/tunnel"
)

// The QUIC inbounds carry every proxied connection as a stream of one QUIC
// connection. These benchmarks measure what a server spends on a short
// proxied connection (new stream, 1-byte request, 64-byte answer, close: the
// "hs" phase of test/bench/compare) and on a new QUIC connection (handshake,
// authentication, one such stream). Client and server share the process, so
// read the server's part from a profile:
//
//	DISABLE_LOOPBACK_DETECTOR=1 go test ./listener/inbound -run '^$' -bench QUIC -cpu 4 -cpuprofile cpu.out
//
// The Tunnel variant needs DISABLE_LOOPBACK_DETECTOR=1: client, server and
// sink share 127.0.0.1, and the detector takes a DIRECT connection whose
// local TCP port equals the client's UDP port for a loop.

// echoTunnel answers every proxied connection like the bench sink: it reads
// the 1-byte request, writes 64 bytes and closes.
func echoTunnel() *TestTunnel {
	answer := make([]byte, 64)
	return &TestTunnel{
		HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) {
			defer conn.Close()
			var b [1]byte
			if _, err := io.ReadFull(conn, b[:]); err != nil {
				return
			}
			_, _ = conn.Write(answer)
		},
		HandleUDPPacketFn: func(packet C.UDPPacket, metadata *C.Metadata) { packet.Drop() },
		CloseFn:           func() error { return nil },
	}
}

// benchSink is a TCP server answering like the bench sink: 64 bytes for a
// 1-byte request, then close.
func benchSink(b *testing.B) netip.AddrPort {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = ln.Close() })
	answer := make([]byte, 64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var req [1]byte
				if _, err := io.ReadFull(c, req[:]); err == nil {
					_, _ = c.Write(answer)
				}
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

var benchTunnelOnce sync.Once

// realTunnel is the tunnel of the core with DIRECT as the only proxy.
func realTunnel() C.Tunnel {
	benchTunnelOnce.Do(func() {
		tunnel.UpdateProxies(map[string]C.Proxy{"DIRECT": adapter.NewProxy(outbound.NewDirect())}, nil)
		tunnel.OnRunning()
	})
	return tunnel.Tunnel
}

func benchShortConn(proxy C.ProxyAdapter, dst netip.AddrPort) error {
	metadata := &C.Metadata{NetWork: C.TCP, DstIP: dst.Addr(), DstPort: dst.Port()}
	conn, err := proxy.DialContext(context.Background(), metadata)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.Write([]byte{1}); err != nil {
		return err
	}
	var buf [64]byte
	_, err = io.ReadFull(conn, buf[:])
	return err
}

func runParallel(b *testing.B, clients int, fn func() error) {
	b.ReportAllocs()
	b.SetParallelism(max(1, clients/runtime.GOMAXPROCS(0)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := fn(); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func benchQUICInbound(b *testing.B, listen func(C.Tunnel) (string, func()), dial func(netip.AddrPort) (C.ProxyAdapter, error)) {
	streams := func(b *testing.B, tunnel C.Tunnel, dst netip.AddrPort) {
		addr, closeIn := listen(tunnel)
		defer closeIn()
		out, err := dial(netip.MustParseAddrPort(addr))
		if err != nil {
			b.Fatal(err)
		}
		defer out.Close()
		if err = benchShortConn(out, dst); err != nil { // the QUIC connection
			b.Fatal(err)
		}
		runParallel(b, 128, func() error { return benchShortConn(out, dst) }) // 128 clients, as in the bench
	}
	echoDst := netip.AddrPortFrom(remoteAddr, 80)

	// the protocol alone: the tunnel answers itself
	b.Run("Streams", func(b *testing.B) { streams(b, echoTunnel(), echoDst) })
	// the whole server: the core's tunnel dials a TCP sink with DIRECT
	b.Run("Tunnel", func(b *testing.B) { streams(b, realTunnel(), benchSink(b)) })
	// a new QUIC connection (handshake, authentication) per proxied connection
	b.Run("Handshakes", func(b *testing.B) {
		addr, closeIn := listen(echoTunnel())
		defer closeIn()
		addrPort := netip.MustParseAddrPort(addr)
		runParallel(b, 16, func() error {
			out, err := dial(addrPort)
			if err != nil {
				return err
			}
			defer out.Close()
			return benchShortConn(out, echoDst)
		})
	})
}

func BenchmarkQUICInboundHysteria2(b *testing.B) {
	benchQUICInbound(b, func(tunnel C.Tunnel) (string, func()) {
		in, err := inbound.NewHysteria2(&inbound.Hysteria2Option{
			BaseOption:  inbound.BaseOption{NameStr: "hysteria2_bench", Listen: "127.0.0.1", Port: "0"},
			Users:       map[string]string{"test": userUUID},
			Certificate: tlsCertificate,
			PrivateKey:  tlsPrivateKey,
		})
		if err != nil {
			b.Fatal(err)
		}
		if err = in.Listen(tunnel); err != nil {
			b.Fatal(err)
		}
		return in.Address(), func() { _ = in.Close() }
	}, func(addrPort netip.AddrPort) (C.ProxyAdapter, error) {
		return outbound.NewHysteria2(outbound.Hysteria2Option{
			Name:        "hysteria2_bench",
			Server:      addrPort.Addr().String(),
			Port:        int(addrPort.Port()),
			Password:    userUUID,
			Fingerprint: tlsFingerprint,
		})
	})
}

func BenchmarkQUICInboundTuic(b *testing.B) {
	benchQUICInbound(b, func(tunnel C.Tunnel) (string, func()) {
		in, err := inbound.NewTuic(&inbound.TuicOption{
			BaseOption:           inbound.BaseOption{NameStr: "tuic_bench", Listen: "127.0.0.1", Port: "0"},
			Users:                map[string]string{userUUID: userUUID},
			Certificate:          tlsCertificate,
			PrivateKey:           tlsPrivateKey,
			CongestionController: "bbr",
		})
		if err != nil {
			b.Fatal(err)
		}
		if err = in.Listen(tunnel); err != nil {
			b.Fatal(err)
		}
		return in.Address(), func() { _ = in.Close() }
	}, func(addrPort netip.AddrPort) (C.ProxyAdapter, error) {
		return outbound.NewTuic(outbound.TuicOption{
			Name:                 "tuic_bench",
			Server:               addrPort.Addr().String(),
			Port:                 int(addrPort.Port()),
			UUID:                 userUUID,
			Password:             userUUID,
			Fingerprint:          tlsFingerprint,
			CongestionController: "bbr",
			MaxOpenStreams:       1024, // one QUIC connection, like the sing-box client of the bench
		})
	})
}
