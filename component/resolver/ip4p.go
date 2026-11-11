package resolver

import (
	"net"
	"net/netip"
	"strconv"

	"github.com/metacubex/mihomo/log"
)

var (
	ip4PEnable bool
)

func GetIP4PEnable() bool {
	return ip4PEnable
}

func SetIP4PEnable(enableIP4PConvert bool) {
	ip4PEnable = enableIP4PConvert
}

// kanged from https://github.com/heiher/frp/blob/ip4p/client/ip4p.go

func LookupIP4P(addr netip.Addr, port string) (netip.Addr, string) {
	// IP4P layout: 2001:0000:0000:0000:0000:PPPP:AAAA:AAAA (port P, IPv4 A).
	// Only IPv6 input is considered (an IPv4 address such as 32.1.0.0 would
	// otherwise match the prefix and be indexed out of range), and bytes 4..9
	// must be zero so that regular Teredo addresses (2001::/32) stay intact.
	if !ip4PEnable || !addr.Is6() {
		return addr, port
	}
	ip := addr.As16()
	if ip[0] != 0x20 || ip[1] != 0x01 || ip[2] != 0x00 || ip[3] != 0x00 {
		return addr, port
	}
	for _, b := range ip[4:10] {
		if b != 0 {
			return addr, port
		}
	}
	newAddr := netip.AddrFrom4([4]byte{ip[12], ip[13], ip[14], ip[15]})
	newPort := strconv.Itoa(int(ip[10])<<8 + int(ip[11]))
	log.Debugln("Convert IP4P address %s to %s", addr, net.JoinHostPort(newAddr.String(), newPort))
	return newAddr, newPort
}
