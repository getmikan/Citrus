package tunnel

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/accept"
	"github.com/metacubex/mihomo/transport/socks5"
)

type Listener struct {
	listener net.Listener
	addr     string
	target   socks5.Addr
	proxy    string
	closed   atomic.Bool
}

// RawAddress implements C.Listener
func (l *Listener) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *Listener) Address() string {
	return l.listener.Addr().String()
}

// Close implements C.Listener
func (l *Listener) Close() error {
	l.closed.Store(true)
	return l.listener.Close()
}

func (l *Listener) handleTCP(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	tunnel.HandleTCPConn(inbound.NewSocket(l.target, conn, C.TUNNEL, additions...))
}

func New(addr, target, proxy string, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	l, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}

	targetAddr := socks5.ParseAddr(target)
	if targetAddr == nil {
		return nil, fmt.Errorf("invalid target address %s", target)
	}

	rl := &Listener{
		listener: l,
		target:   targetAddr,
		proxy:    proxy,
		addr:     addr,
	}

	if proxy != "" {
		additions = append([]inbound.Addition{inbound.WithSpecialProxy(proxy)}, additions...)
	}

	go func() {
		for {
			c, err := accept.Next(l, rl.closed.Load)
			if err != nil {
				break
			}
			go rl.handleTCP(c, tunnel, additions...)
		}
	}()

	return rl, nil
}
