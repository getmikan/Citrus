package loopback

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"

	"github.com/metacubex/mihomo/common/callback"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/iface"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
)

var disableLoopBackDetector, _ = strconv.ParseBool(os.Getenv("DISABLE_LOOPBACK_DETECTOR"))

func init() {
	if features.CMFA {
		disableLoopBackDetector = true
	}
}

var ErrReject = errors.New("reject loopback connection")

// connKey is the 4-tuple of a DIRECT TCP connection, as seen from its own
// side: local is the source address the kernel chose, remote is the address
// it dialed.
type connKey struct {
	local  netip.AddrPort
	remote netip.AddrPort
}

type Detector struct {
	// connMap holds the 4-tuples of the live DIRECT TCP connections. The
	// source address alone is not enough: the kernel hands the same
	// ephemeral port to connections towards different destinations, so a
	// legitimate local client may share it with a DIRECT connection.
	connMap xsync.Map[connKey, struct{}]
	// packetConnMap holds the bound local addresses of the live DIRECT UDP
	// sockets. They are unconnected (one socket talks to any destination),
	// so there is no remote half; the bound address, including its IP when
	// the socket is not bound to the wildcard, is what identifies them.
	packetConnMap xsync.Map[netip.AddrPort, struct{}]
}

func NewDetector() *Detector {
	if disableLoopBackDetector {
		return nil
	}
	return &Detector{}
}

func addrPortOf(addr net.Addr) netip.AddrPort {
	metadata := C.Metadata{}
	if metadata.SetRemoteAddr(addr) != nil {
		return netip.AddrPort{}
	}
	return metadata.AddrPort()
}

func (l *Detector) NewConn(conn C.Conn) C.Conn {
	if l == nil {
		return conn
	}
	key := connKey{local: addrPortOf(conn.LocalAddr()), remote: addrPortOf(conn.RemoteAddr())}
	if !key.local.IsValid() || !key.remote.IsValid() {
		return conn
	}
	l.connMap.Store(key, struct{}{})
	return callback.NewCloseCallbackConn(conn, func() {
		l.connMap.Delete(key)
	})
}

func (l *Detector) NewPacketConn(conn C.PacketConn) C.PacketConn {
	if l == nil {
		return conn
	}
	connAddr := addrPortOf(conn.LocalAddr())
	if !connAddr.IsValid() {
		return conn
	}
	l.packetConnMap.Store(connAddr, struct{}{})
	return callback.NewCloseCallbackPacketConn(conn, func() {
		l.packetConnMap.Delete(connAddr)
	})
}

// CheckConn reports a loop when the incoming connection described by metadata
// is one of DIRECT's own connections coming back: its source is the local
// address of a live DIRECT connection and its destination is that
// connection's remote address. The destination is the inbound's local address
// (InIP:InPort) when DIRECT dialed a Citrus listener, or the original
// destination (DstIP:DstPort) when the connection was captured transparently
// (tun, tproxy, redir); both are tried.
func (l *Detector) CheckConn(metadata *C.Metadata) error {
	if l == nil {
		return nil
	}
	src := metadata.SourceAddrPort()
	if !src.IsValid() {
		return nil
	}
	for _, dst := range [...]netip.AddrPort{
		netip.AddrPortFrom(metadata.InIP.Unmap(), metadata.InPort),
		metadata.AddrPort(),
	} {
		if !dst.IsValid() || dst.Port() == 0 {
			continue
		}
		if _, ok := l.connMap.Load(connKey{local: src, remote: dst}); ok {
			return fmt.Errorf("%w to: %s", ErrReject, metadata.RemoteAddress())
		}
	}
	return nil
}

// CheckPacketConn reports a loop when the incoming UDP session comes from a
// local address that a live DIRECT UDP socket is bound to, either exactly or
// through the wildcard address of its family.
func (l *Detector) CheckPacketConn(metadata *C.Metadata) error {
	if l == nil {
		return nil
	}
	connAddr := metadata.SourceAddrPort()
	if !connAddr.IsValid() {
		return nil
	}

	isLocalIp, err := iface.IsLocalIp(connAddr.Addr())
	if err != nil {
		return err
	}
	if !isLocalIp && !connAddr.Addr().IsLoopback() {
		return nil
	}

	port := connAddr.Port()
	for _, bound := range [...]netip.AddrPort{
		connAddr,
		netip.AddrPortFrom(netip.IPv4Unspecified(), port),
		netip.AddrPortFrom(netip.IPv6Unspecified(), port),
	} {
		if _, ok := l.packetConnMap.Load(bound); ok {
			return fmt.Errorf("%w to: %s", ErrReject, metadata.RemoteAddress())
		}
	}
	return nil
}
