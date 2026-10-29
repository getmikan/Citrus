//go:build linux

package outbound

import (
	"net"
	"syscall"
)

// ipv6RecvHopLimit is IPV6_RECVHOPLIMIT from in6.h, the same on every Linux
// architecture.
const ipv6RecvHopLimit = 0x33

// desyncStopHopRecording turns off the received hop limit recording that
// desync.ControlAutoTTL enabled before connect: while it is on, the kernel
// clones every received in-order segment. Errors are ignored; an IPv4
// socket never had it on.
func desyncStopHopRecording(c net.Conn) {
	for i := 0; i < 8 && c != nil; i++ {
		if sc, ok := c.(syscall.Conn); ok {
			if raw, err := sc.SyscallConn(); err == nil {
				_ = raw.Control(func(fd uintptr) {
					_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6RecvHopLimit, 0)
				})
			}
			return
		}
		u, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			return
		}
		c = u.NetConn()
	}
}
