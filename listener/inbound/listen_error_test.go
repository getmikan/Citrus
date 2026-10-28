package inbound_test

import (
	"net"
	"strconv"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/listener/internal/porttest"

	"github.com/stretchr/testify/require"
)

// twoPorts returns a free port and a port held on network, the busy one
// higher so that the inbound reaches it second.
func twoPorts(t *testing.T, network string) (free int, busy int) {
	t.Helper()
	return port(porttest.FreeAddr(t)), port(porttest.BusyAddr(t, network))
}

func port(addr string) int {
	_, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return n
}

func requirePortFree(t *testing.T, port int) {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	porttest.RequireFree(t, "tcp", addr)
	porttest.RequireFree(t, "udp", addr)
}

func portsOption(name string, free, busy int) inbound.BaseOption {
	return inbound.BaseOption{
		NameStr: name,
		Listen:  "127.0.0.1",
		Port:    strconv.Itoa(free) + "," + strconv.Itoa(busy),
	}
}

// A later address failing must not leave the earlier ones listening: the
// failed inbound is never closed by its caller.
func TestInboundListenLaterAddressFailsFreesEarlier(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network string // the one that is busy on the second port
		new     func(base inbound.BaseOption) (C.InboundListener, error)
	}{
		{"http", "tcp", func(base inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewHTTP(&inbound.HTTPOption{BaseOption: base})
		}},
		{"socks-tcp", "tcp", func(base inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewSocks(&inbound.SocksOption{BaseOption: base, UDP: true})
		}},
		{"socks-udp", "udp", func(base inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewSocks(&inbound.SocksOption{BaseOption: base, UDP: true})
		}},
		{"mixed-tcp", "tcp", func(base inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewMixed(&inbound.MixedOption{BaseOption: base, UDP: true})
		}},
		{"mixed-udp", "udp", func(base inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewMixed(&inbound.MixedOption{BaseOption: base, UDP: true})
		}},
		{"tunnel", "udp", func(base inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewTunnel(&inbound.TunnelOption{BaseOption: base, Network: []string{"tcp", "udp"}, Target: "127.0.0.1:53"})
		}},
		{"sudoku", "tcp", func(base inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewSudoku(&inbound.SudokuOption{BaseOption: base, Key: "test_key"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			free, busy := twoPorts(t, tc.network)
			in, err := tc.new(portsOption(tc.name+"-inbound", free, busy))
			require.NoError(t, err)
			require.Error(t, in.Listen(nil))
			requirePortFree(t, free)
		})
	}
}
