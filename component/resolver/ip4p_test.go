package resolver

import (
	"net/netip"
	"testing"
)

func TestLookupIP4P(t *testing.T) {
	prev := GetIP4PEnable()
	SetIP4PEnable(true)
	defer SetIP4PEnable(prev)

	tests := []struct {
		name     string
		addr     string
		wantAddr string
		wantPort string
	}{
		// 2001::1f90:c0a8:101 -> 192.168.1.1:8080
		{"ip4p", "2001::1f90:c0a8:101", "192.168.1.1", "8080"},
		// An IPv4 address whose bytes match the prefix must not panic or convert.
		{"ipv4 32.1.0.0", "32.1.0.0", "32.1.0.0", "443"},
		// A Teredo address (server IPv4 in bytes 4..7) is not IP4P.
		{"teredo", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "443"},
		{"plain ipv6", "2001:db8::1", "2001:db8::1", "443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAddr, gotPort := LookupIP4P(netip.MustParseAddr(tt.addr), "443")
			if gotAddr != netip.MustParseAddr(tt.wantAddr) || gotPort != tt.wantPort {
				t.Fatalf("LookupIP4P(%s) = %s, %s; want %s, %s", tt.addr, gotAddr, gotPort, tt.wantAddr, tt.wantPort)
			}
		})
	}

	SetIP4PEnable(false)
	in := netip.MustParseAddr("2001::1f90:c0a8:101")
	if a, p := LookupIP4P(in, "443"); a != in || p != "443" {
		t.Fatalf("disabled conversion changed address: %s %s", a, p)
	}
}
