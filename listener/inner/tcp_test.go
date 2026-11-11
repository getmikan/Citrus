package inner

import (
	"net"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type recordTunnel struct {
	C.Tunnel
	got chan *C.Metadata
}

func (t *recordTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	_ = conn.Close()
	t.got <- metadata
}

func TestHandleTcpResolvedKeepsHost(t *testing.T) {
	tun := &recordTunnel{got: make(chan *C.Metadata, 1)}
	ip := netip.MustParseAddr("203.0.113.10")
	conn, err := HandleTcpResolved(tun, "cdn.example:443", ip, "PROXY")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	m := <-tun.got
	if m.Host != "cdn.example" || m.DstIP != ip || !m.DstIPChecked || m.DstPort != 443 || m.SpecialProxy != "PROXY" {
		t.Fatalf("metadata = host %q ip %v checked %v port %d proxy %q", m.Host, m.DstIP, m.DstIPChecked, m.DstPort, m.SpecialProxy)
	}
	if m.RemoteAddress() != "cdn.example:443" {
		t.Fatalf("proxies would receive %s, want the host name", m.RemoteAddress())
	}

	conn2, err := HandleTcp(tun, "cdn.example:443", "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	if m := <-tun.got; m.DstIP.IsValid() || m.DstIPChecked {
		t.Fatalf("HandleTcp pinned an address: %v", m.DstIP)
	}
}
