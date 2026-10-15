// Package publicaddr tells whether a destination chosen by an unauthenticated
// client is a host on the public internet, so that fallbacks which dial such a
// destination cannot be turned against the server's own network (SSRF).
package publicaddr

import (
	"net/netip"
	"strings"
)

// nonPublicPrefixes are the special-purpose ranges that netip has no predicate
// for. Loopback, RFC 1918, ULA, link-local, multicast and unspecified addresses
// are checked through the netip methods in IsPublicIP.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT, also Tailscale and similar overlays
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking, also the default fake-ip range
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved and limited broadcast
	netip.MustParsePrefix("::/96"),           // IPv4-compatible, deprecated
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("fec0::/10"),       // site-local, deprecated
}

// cloudMetadata are metadata services outside the ranges above;
// 169.254.169.254 and fe80::/10 are link-local already.
var cloudMetadata = []netip.Addr{
	netip.MustParseAddr("fd00:ec2::254"),   // AWS, IPv6
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud
}

var (
	nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour   = netip.MustParsePrefix("2002::/16")
)

// IsPublicIP reports whether addr is a globally routable unicast address that is
// not a cloud metadata service. Addresses that embed an IPv4 address (IPv4-mapped,
// NAT64 and 6to4) are judged by the embedded address.
func IsPublicIP(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return false
	}
	if addr.Is6() {
		if nat64Prefix.Contains(addr) {
			raw := addr.As16()
			return IsPublicIP(netip.AddrFrom4([4]byte(raw[12:16])))
		}
		if sixToFour.Contains(addr) {
			raw := addr.As16()
			return IsPublicIP(netip.AddrFrom4([4]byte(raw[2:6])))
		}
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() || addr.IsMulticast() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	for _, metadata := range cloudMetadata {
		if addr == metadata {
			return false
		}
	}
	return true
}

// nonPublicSuffixes are names that only resolve inside a host or a local network.
var nonPublicSuffixes = []string{
	"localhost",
	"local",
	"internal",
	"home.arpa",
	"arpa",
}

// IsPublicHostname reports whether name is a syntactically valid, fully qualified
// DNS host name that may name a host on the public internet: at least two labels
// of letters, digits and inner hyphens, no IP literal (including the numeric
// shorthands such as 127.1 or 0x7f.1, rejected through an all-numeric last label),
// no trailing dot, and no localhost or local-only suffix. The name still has to
// be resolved and every address checked with IsPublicIP before it is dialed.
func IsPublicHostname(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	name = strings.ToLower(name)
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !validLabel(label) {
			return false
		}
	}
	if isNumeric(labels[len(labels)-1]) || strings.HasPrefix(labels[len(labels)-1], "0x") {
		return false
	}
	for _, suffix := range nonPublicSuffixes {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return false
		}
	}
	return true
}

func validLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func isNumeric(label string) bool {
	for i := 0; i < len(label); i++ {
		if label[i] < '0' || label[i] > '9' {
			return false
		}
	}
	return true
}
