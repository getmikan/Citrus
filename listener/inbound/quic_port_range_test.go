package inbound_test

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/require"
)

// TestInboundQUIC_PortRangeCost listens on a range of 1000 ports with no
// clients: the QUIC listeners run one server for the whole range, so an idle
// port costs a socket and one reading goroutine, not a QUIC server.
func TestInboundQUIC_PortRangeCost(t *testing.T) {
	if testing.Short() {
		t.Skip("opens 1000 sockets per listener")
	}
	const ports = 1000
	for _, test := range []struct {
		name   string
		listen func(base inbound.BaseOption) (C.InboundListener, error)
	}{
		{"hysteria2", func(base inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewHysteria2(&inbound.Hysteria2Option{BaseOption: base,
				Users: map[string]string{"test": userUUID}, Certificate: tlsCertificate, PrivateKey: tlsPrivateKey})
		}},
		{"hysteria2-salamander", func(base inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewHysteria2(&inbound.Hysteria2Option{BaseOption: base,
				Users: map[string]string{"test": userUUID}, Certificate: tlsCertificate, PrivateKey: tlsPrivateKey,
				Obfs: "salamander", ObfsPassword: userUUID})
		}},
		{"tuic", func(base inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewTuic(&inbound.TuicOption{BaseOption: base,
				Users: map[string]string{userUUID: userUUID}, Certificate: tlsCertificate, PrivateKey: tlsPrivateKey})
		}},
		{"shadowquic", func(base inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewShadowQuic(&inbound.ShadowQuicOption{BaseOption: base,
				Users:       []inbound.ShadowQuicUser{{Username: "user", Password: userUUID}},
				JLSUpstream: inbound.ShadowQuicJLSUpstream{Addr: "127.0.0.1:1"}})
		}},
		{"trusttunnel-udp", func(base inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewTrustTunnel(&inbound.TrustTunnelOption{BaseOption: base,
				Users: inbound.AuthUsers{{Username: "user", Password: userUUID}}, Certificate: tlsCertificate, PrivateKey: tlsPrivateKey,
				Network: []string{"udp"}})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			first := freeUDPRange(t, ports)
			in, err := test.listen(inbound.BaseOption{NameStr: test.name + "_range", Listen: "127.0.0.1",
				Port: fmt.Sprintf("%d-%d", first, first+ports-1)})
			require.NoError(t, err)
			tunnel := NewHttpTestTunnel()
			defer tunnel.Close()

			goroutines, memory := runtime.NumGoroutine(), memoryInUse()
			require.NoError(t, in.Listen(tunnel))
			time.Sleep(200 * time.Millisecond) // let the servers start
			goroutines, memory = runtime.NumGoroutine()-goroutines, memoryInUse()-memory
			require.NoError(t, in.Close())
			t.Logf("%d ports: %d goroutines, %.1f MiB of heap and stacks", ports, goroutines, float64(memory)/(1<<20))
			// one reader per port and a few for the one server
			require.LessOrEqual(t, goroutines, ports+50)
		})
	}
}

func memoryInUse() int64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapInuse + m.StackInuse)
}
