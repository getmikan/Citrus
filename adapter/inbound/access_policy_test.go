package inbound

import (
	"net"
	"net/netip"
	"sync"
	"testing"
)

func TestAccessPolicyIsOneImmutableGeneration(t *testing.T) {
	old := loadAccessPolicy()
	t.Cleanup(func() { SetAccessPolicy(old.skipAuth, old.allowed, old.denied) })
	loopback := netip.MustParsePrefix("127.0.0.0/8")
	all := netip.MustParsePrefix("0.0.0.0/0")
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
	SetAccessPolicy(nil, []netip.Prefix{all}, []netip.Prefix{loopback})

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				SetAccessPolicy(nil, []netip.Prefix{all}, []netip.Prefix{loopback})
				SetAccessPolicy([]netip.Prefix{loopback}, []netip.Prefix{all}, nil)
			}
		}()
	}
	for range 4000 {
		allowed, skip := EvaluateRemoteAddr(addr)
		if allowed && !skip {
			t.Fatal("observed a mixed access-policy generation")
		}
	}
	wg.Wait()
}

func TestAccessPolicyCopiesInputAndOutput(t *testing.T) {
	old := loadAccessPolicy()
	t.Cleanup(func() { SetAccessPolicy(old.skipAuth, old.allowed, old.denied) })
	input := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	SetAccessPolicy(input, input, nil)
	input[0] = netip.MustParsePrefix("10.0.0.0/8")
	got := AllowedIPs()
	got[0] = netip.MustParsePrefix("192.168.0.0/16")
	if AllowedIPs()[0] != netip.MustParsePrefix("127.0.0.0/8") {
		t.Fatal("published policy was mutated through a caller slice")
	}
}
