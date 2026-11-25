package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/wireguard-go/conn"
)

// Endpoint is the peer address as the server device knows it. Unlike the
// client bind's endpoint it carries no socket state: the server has one UDP
// socket for every peer, so a packet's sender is all the routing information
// the device needs.
type Endpoint struct {
	AddrPort netip.AddrPort
}

var _ conn.Endpoint = (*Endpoint)(nil)

func (e *Endpoint) ClearSrc()           {}
func (e *Endpoint) SrcToString() string { return "" }
func (e *Endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *Endpoint) DstIP() netip.Addr   { return e.AddrPort.Addr() }
func (e *Endpoint) DstToString() string { return e.AddrPort.String() }

func (e *Endpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

// Bind is the server side of the WireGuard transport: one UDP socket shared by
// every peer, owned by the bind because the device opens and closes its network
// side on every configuration reload.
//
// The socket comes from the inbound listen config, so the node's routing mark
// and socket options apply to it like to any other inbound.
type Bind struct {
	lc   listenConfig
	addr string

	mu     sync.Mutex
	conn   net.PacketConn
	bound  string
	closed bool
}

var _ conn.Bind = (*Bind)(nil)

// NewBind opens the socket of the listener address.
func NewBind(lc listenConfig, addr string) (*Bind, error) {
	b := &Bind{lc: lc, addr: addr}
	if err := b.open(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *Bind) open() error {
	pc, err := b.lc.ListenPacket(context.Background(), "udp", b.addr)
	if err != nil {
		return err
	}
	b.mu.Lock()
	prev := b.conn
	b.conn = pc
	// The address the first socket got: a reload must land on the same port, so
	// a concrete port replaces a wildcard one.
	if b.bound == "" {
		b.bound = pc.LocalAddr().String()
	}
	b.mu.Unlock()
	if prev != nil {
		_ = prev.Close()
	}
	return nil
}

// Addr is the address the listener is bound to.
func (b *Bind) Addr() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.bound
}

func (b *Bind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	// The device closes the bind at the start of every update and opens it
	// again: a closed socket is reopened on the address the listener already
	// reported, so a configuration reload keeps the port.
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return nil, 0, net.ErrClosed
	}
	if b.packetConn() == nil {
		if err := b.reopen(); err != nil {
			return nil, 0, err
		}
	}
	pc := b.packetConn()
	if pc == nil {
		return nil, 0, net.ErrClosed
	}
	udpAddr, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, 0, errors.New("wireguard: unexpected socket address")
	}
	return []conn.ReceiveFunc{b.receive}, uint16(udpAddr.Port), nil
}

func (b *Bind) packetConn() net.PacketConn {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conn
}

func (b *Bind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	pc := b.packetConn()
	if pc == nil {
		return 0, net.ErrClosed
	}
	n, addr, err := pc.ReadFrom(packets[0])
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return 0, net.ErrClosed
		}
		return 0, fmt.Errorf("wireguard: receive: %w", err)
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("wireguard: unexpected packet source address")
	}
	sizes[0] = n
	eps[0] = &Endpoint{AddrPort: udpAddr.AddrPort()}
	return 1, nil
}

// reopen binds the socket again after the device closed it, on the address the
// listener reports.
func (b *Bind) reopen() error {
	b.mu.Lock()
	addr := b.bound
	lc := b.lc
	b.mu.Unlock()
	if addr == "" {
		return net.ErrClosed
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.conn = pc
	b.mu.Unlock()
	return nil
}

// Close closes the current socket and lets the device open a new one: the
// device calls it at the start of every bind update.
func (b *Bind) Close() error {
	b.mu.Lock()
	pc := b.conn
	b.conn = nil
	b.mu.Unlock()
	if pc == nil {
		return nil
	}
	return pc.Close()
}

// Shutdown closes the socket for good; the listener calls it on close.
func (b *Bind) Shutdown() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return b.Close()
}

func (b *Bind) SetMark(mark uint32) error { return nil }

func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*Endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	pc := b.packetConn()
	if pc == nil {
		return net.ErrClosed
	}
	var firstErr error
	for _, buf := range bufs {
		if _, err := pc.WriteTo(buf, net.UDPAddrFromAddrPort(e.AddrPort)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &Endpoint{AddrPort: ap}, nil
}

func (b *Bind) BatchSize() int { return 1 }

// listenConfig is the part of constant.InboundListenConfig the listener uses.
type listenConfig interface {
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}
