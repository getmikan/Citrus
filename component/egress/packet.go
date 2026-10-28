package egress

import (
	"net"
	"sync/atomic"
	"syscall"

	"github.com/metacubex/mihomo/common/net/packet"
	"github.com/metacubex/mihomo/log"
)

// NewPacketConn guards a DIRECT UDP socket: datagrams to a blocked address
// are dropped, and so are the datagrams that arrive from one (the socket is
// unconnected, any host that learns its port can send to it).
func NewPacketConn(pc net.PacketConn, g *Guard) net.PacketConn {
	gpc := &packetConn{EnhancePacketConn: packet.NewEnhancePacketConn(pc), guard: g}
	if sc, ok := pc.(syscall.Conn); ok {
		// keeps the socket recognisable as a system conn, which reads
		// deadlines correctly and needs no deadline wrapper
		return &syscallPacketConn{packetConn: gpc, sc: sc}
	}
	return gpc
}

type packetConn struct {
	packet.EnhancePacketConn
	guard  *Guard
	logged atomic.Bool
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if err := c.guard.checkNetAddr(addr); err != nil {
		if c.logged.CompareAndSwap(false, true) {
			log.Warnln("[UDP] %s, dropping the datagrams of this session to blocked addresses", err)
		} else {
			log.Debugln("[UDP] %s", err)
		}
		return len(p), nil // dropped like a lost datagram, the session goes on
	}
	return c.EnhancePacketConn.WriteTo(p, addr)
}

func (c *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = c.EnhancePacketConn.ReadFrom(p)
		if err != nil || c.guard.checkNetAddr(addr) == nil {
			return
		}
		log.Debugln("[UDP] egress guard dropped a datagram from %s", addr)
	}
}

func (c *packetConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	for {
		data, put, addr, err = c.EnhancePacketConn.WaitReadFrom()
		if err != nil || c.guard.checkNetAddr(addr) == nil {
			return
		}
		if put != nil {
			put()
		}
		log.Debugln("[UDP] egress guard dropped a datagram from %s", addr)
	}
}

type syscallPacketConn struct {
	*packetConn
	sc syscall.Conn
}

func (c *syscallPacketConn) SyscallConn() (syscall.RawConn, error) {
	return c.sc.SyscallConn()
}
