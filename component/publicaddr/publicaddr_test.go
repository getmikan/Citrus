package publicaddr

import (
	"net/netip"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	testCases := map[string]bool{
		"93.184.216.34":        true,
		"1.1.1.1":              true,
		"2606:4700::1111":      true,
		"2002:5db8:d822::1":    true, // 6to4 of 93.184.216.34
		"64:ff9b::5db8:d822":   true, // NAT64 of 93.184.216.34
		"127.0.0.1":            false,
		"::1":                  false,
		"10.1.2.3":             false,
		"172.16.0.1":           false,
		"192.168.1.1":          false,
		"fc00::1":              false,
		"fd12:3456::1":         false,
		"169.254.169.254":      false,
		"fe80::1":              false,
		"224.0.0.1":            false,
		"ff02::1":              false,
		"0.0.0.0":              false,
		"0.1.2.3":              false,
		"::":                   false,
		"100.64.0.1":           false,
		"100.127.255.254":      false,
		"100.100.100.200":      false,
		"fd00:ec2::254":        false,
		"198.18.0.1":           false,
		"255.255.255.255":      false,
		"192.0.2.1":            false,
		"2001:db8::1":          false,
		"::ffff:10.0.0.1":      false,
		"::ffff:127.0.0.1":     false,
		"64:ff9b::a00:1":       false, // NAT64 of 10.0.0.1
		"2002:a9fe:a9fe::1":    false, // 6to4 of 169.254.169.254
		"::127.0.0.1":          false,
		"fec0::1":              false,
		"64:ff9b:1::5db8:d822": false,
	}
	for input, want := range testCases {
		if got := IsPublicIP(netip.MustParseAddr(input)); got != want {
			t.Errorf("IsPublicIP(%s) = %v, want %v", input, got, want)
		}
	}
	if IsPublicIP(netip.Addr{}) {
		t.Error("IsPublicIP(zero) = true, want false")
	}
}

func TestIsPublicHostname(t *testing.T) {
	testCases := map[string]bool{
		"example.com":              true,
		"www.Example.COM":          true,
		"xn--80ak6aa92e.com":       true,
		"a-b.example.co.uk":        true,
		"":                         false,
		"localhost":                false,
		"LOCALHOST":                false,
		"foo.localhost":            false,
		"printer.local":            false,
		"metadata.google.internal": false,
		"router.home.arpa":         false,
		"1.0.0.127.in-addr.arpa":   false,
		"intranet":                 false,
		"example.com.":             false,
		".example.com":             false,
		"a..example.com":           false,
		"-a.example.com":           false,
		"a-.example.com":           false,
		"under_score.example.com":  false,
		"127.0.0.1":                false,
		"127.1":                    false,
		"2130706433":               false,
		"0x7f.0x1":                 false,
		"::1":                      false,
		"[::1]":                    false,
		"example.com:443":          false,
		"exa mple.com":             false,
	}
	for input, want := range testCases {
		if got := IsPublicHostname(input); got != want {
			t.Errorf("IsPublicHostname(%q) = %v, want %v", input, got, want)
		}
	}
}
