package inner

import (
	"errors"
	"net"
	"net/netip"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

var tunnel C.Tunnel

func New(t C.Tunnel) {
	tunnel = t
}

func GetTunnel() C.Tunnel {
	return tunnel
}

func HandleTcp(tunnel C.Tunnel, address string, proxy string) (conn net.Conn, err error) {
	return handleTcp(tunnel, address, netip.Addr{}, proxy)
}

// HandleTcpResolved is HandleTcp for a host name the caller has already
// resolved and validated as dstIP. Rules still see the host name and a proxy
// still receives it, but IP rules match dstIP and DIRECT dials dstIP instead
// of resolving the name again.
func HandleTcpResolved(tunnel C.Tunnel, address string, dstIP netip.Addr, proxy string) (conn net.Conn, err error) {
	return handleTcp(tunnel, address, dstIP, proxy)
}

func handleTcp(tunnel C.Tunnel, address string, dstIP netip.Addr, proxy string) (conn net.Conn, err error) {
	if tunnel == nil {
		return nil, errors.New("tunnel uninitialized")
	}

	metadata := &C.Metadata{}
	metadata.NetWork = C.TCP
	metadata.Type = C.INNER
	metadata.DNSMode = C.DNSNormal
	metadata.Process = C.MihomoName
	if proxy != "" {
		metadata.SpecialProxy = proxy
	}
	if err = metadata.SetRemoteAddress(address); err != nil {
		return nil, err
	}
	if dstIP.IsValid() && metadata.Host != "" {
		metadata.DstIP = dstIP.Unmap()
		metadata.DstIPChecked = true
	}

	// executor Parsed
	conn1, conn2 := N.Pipe()
	go tunnel.HandleTCPConn(conn2, metadata)
	return conn1, nil
}
