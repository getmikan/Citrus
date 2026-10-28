package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// refuseFilter refuses the addresses of its set.
type refuseFilter map[netip.Addr]bool

var errRefused = errors.New("refused")

func (f refuseFilter) CheckAddr(addr netip.Addr) error {
	if f[addr] {
		return errRefused
	}
	return nil
}

func TestFilterAddrs(t *testing.T) {
	a, b, c := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.2")
	ips := []netip.Addr{a, b, c}

	kept, err := filterAddrs(ips, refuseFilter{a: true, c: true})
	if err != nil || len(kept) != 1 || kept[0] != b {
		t.Fatalf("filterAddrs = %v, %v; want [%s]", kept, err, b)
	}
	if ips[0] != a || ips[1] != b || ips[2] != c {
		t.Fatalf("filterAddrs modified its input: %v", ips)
	}

	if _, err := filterAddrs(ips, refuseFilter{a: true, b: true, c: true}); !errors.Is(err, errRefused) {
		t.Fatalf("all refused: err = %v, want the filter's error", err)
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
