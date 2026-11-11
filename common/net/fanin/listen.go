package fanin

import (
	"context"
	"net"
	"strings"
)

// PacketListener opens UDP sockets (constant.InboundListenConfig is one).
type PacketListener interface {
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

// Listen opens a UDP socket for every comma-separated address of listen and
// returns one conn per host: the ports of one host (an expanded port range)
// are joined into one fan-in conn, a host with a single port keeps its plain
// socket. Addresses on different hosts stay apart, since a client of one
// host never moves to another. prepare, if not nil, is called on every new
// socket. On error the sockets opened so far are closed.
func Listen(ctx context.Context, lc PacketListener, listen string, prepare func(net.PacketConn)) ([]net.PacketConn, error) {
	return listenAll(ctx, lc, listen, prepare, true)
}

// ListenEach is Listen without the joining: one plain socket per address,
// for a server that needs a *net.UDPConn.
func ListenEach(ctx context.Context, lc PacketListener, listen string, prepare func(net.PacketConn)) ([]net.PacketConn, error) {
	return listenAll(ctx, lc, listen, prepare, false)
}

func listenAll(ctx context.Context, lc PacketListener, listen string, prepare func(net.PacketConn), join bool) ([]net.PacketConn, error) {
	var (
		hosts  []string
		groups = make(map[string][]net.PacketConn)
	)
	closeAll := func() {
		for _, group := range groups {
			for _, pc := range group {
				_ = pc.Close()
			}
		}
	}
	for _, addr := range strings.Split(listen, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil || !join {
			host = addr // a group of its own
		}
		pc, err := lc.ListenPacket(ctx, "udp", addr)
		if err != nil {
			closeAll()
			return nil, err
		}
		if prepare != nil {
			prepare(pc)
		}
		if _, ok := groups[host]; !ok {
			hosts = append(hosts, host)
		}
		groups[host] = append(groups[host], pc)
	}
	conns := make([]net.PacketConn, 0, len(hosts))
	for _, host := range hosts {
		group := groups[host]
		if len(group) == 1 {
			conns = append(conns, group[0])
		} else {
			conns = append(conns, New(group))
		}
	}
	return conns, nil
}
