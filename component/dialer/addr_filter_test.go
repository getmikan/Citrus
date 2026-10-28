package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
)

// refuseFilter refuses the addresses of its set.
type refuseFilter map[netip.Addr]bool

var errRefused = errors.New("refused")

func (f refuseFilter) CheckAddrPort(ap netip.AddrPort) error {
	if f[ap.Addr()] {
		return errRefused
	}
	return nil
}

func TestFilterAddrs(t *testing.T) {
	a, b, c := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.2")
	ips := []netip.Addr{a, b, c}

	kept, err := filterAddrs(ips, "443", refuseFilter{a: true, c: true})
	if err != nil || len(kept) != 1 || kept[0] != b {
		t.Fatalf("filterAddrs = %v, %v; want [%s]", kept, err, b)
	}
	if ips[0] != a || ips[1] != b || ips[2] != c {
		t.Fatalf("filterAddrs modified its input: %v", ips)
	}

	if _, err := filterAddrs(ips, "443", refuseFilter{a: true, b: true, c: true}); !errors.Is(err, errRefused) {
		t.Fatalf("all refused: err = %v, want the filter's error", err)
	}
}

// portFilter records the destinations it is asked about.
type portFilter struct{ seen []netip.AddrPort }

func (f *portFilter) CheckAddrPort(ap netip.AddrPort) error {
	f.seen = append(f.seen, ap)
	return nil
}

// The filter sees the port, and for an IP4P address the IPv4 address and port
// the dial goes to, not the IPv6 form it is encoded in.
func TestFilterAddrsIP4P(t *testing.T) {
	old := resolver.GetIP4PEnable()
	resolver.SetIP4PEnable(true)
	t.Cleanup(func() { resolver.SetIP4PEnable(old) })

	ip4p := netip.MustParseAddr("2001::1f90:7f00:1") // 127.0.0.1:8080
	f := &portFilter{}
	kept, err := filterAddrs([]netip.Addr{ip4p, netip.MustParseAddr("1.1.1.1")}, "443", f)
	if err != nil || len(kept) != 2 || kept[0] != ip4p {
		t.Fatalf("filterAddrs = %v, %v; want both addresses as given", kept, err)
	}
	want := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:8080"), netip.MustParseAddrPort("1.1.1.1:443")}
	if len(f.seen) != 2 || f.seen[0] != want[0] || f.seen[1] != want[1] {
		t.Fatalf("filter saw %v, want %v", f.seen, want)
	}
}

// DialContext asks the filter before it connects, for an IP literal as well.
func TestDialContextAddrFilter(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	addr := ln.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = DialContext(ctx, "tcp", addr, WithAddrFilter(refuseFilter{netip.MustParseAddr("127.0.0.1"): true}))
	if !errors.Is(err, errRefused) {
		t.Fatalf("refused literal: err = %v, want the filter's error", err)
	}

	c, err := DialContext(ctx, "tcp", addr, WithAddrFilter(refuseFilter{}))
	if err != nil {
		t.Fatalf("accepted literal: %v", err)
	}
	_ = c.Close()
}
