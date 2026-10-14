package socks

import (
	"net"
	"net/netip"
	"sync"
)

// UDP ASSOCIATE bookkeeping (RFC 1928 §7): a SOCKS5 UDP relay should only carry
// datagrams for clients that negotiated an association over TCP, and only while
// that TCP control connection is open. Associations are kept per listener's
// local port (the TCP and UDP listeners of one inbound share it) and client IP
// address.
//
// An association belongs to the user that authenticated its control
// connection and to one UDP source port of the client: the port the client
// named in the request when it named its own address, otherwise the port of
// the first datagram that claims it. Datagrams from another port of the same
// IP (another client behind the same NAT) do not ride on it, and every
// datagram carries the association's user.

type associationKey struct {
	port uint16
	ip   netip.Addr
}

type association struct {
	user string
	port uint16 // the client's UDP source port; 0 until the first datagram
}

var associations = struct {
	sync.Mutex
	byKey map[associationKey][]*association
}{byKey: make(map[associationKey][]*association)}

func newAssociationKey(local, remote net.Addr) (associationKey, netip.AddrPort, bool) {
	localAddr, ok := addrPort(local)
	if !ok {
		return associationKey{}, netip.AddrPort{}, false
	}
	remoteAddr, ok := addrPort(remote)
	if !ok {
		return associationKey{}, netip.AddrPort{}, false
	}
	return associationKey{port: localAddr.Port(), ip: remoteAddr.Addr()}, remoteAddr, true
}

func addrPort(addr net.Addr) (netip.AddrPort, bool) {
	var ap netip.AddrPort
	switch a := addr.(type) {
	case *net.TCPAddr:
		ap = a.AddrPort()
	case *net.UDPAddr:
		ap = a.AddrPort()
	default:
		if addr == nil {
			return netip.AddrPort{}, false
		}
		parsed, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			return netip.AddrPort{}, false
		}
		ap = parsed
	}
	if !ap.IsValid() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port()), true
}

// addAssociation records an association of user for the control connection
// with the given local and remote addresses. requested is the client address
// of the UDP ASSOCIATE request (nil or unspecified when the client did not
// name it). The returned func removes the association again.
func addAssociation(local, remote net.Addr, user string, requested *net.UDPAddr) (release func()) {
	key, remoteAddr, ok := newAssociationKey(local, remote)
	if !ok {
		return func() {}
	}
	a := &association{user: user}
	if requested != nil {
		if req, ok := addrPort(requested); ok && req.Addr() == remoteAddr.Addr() {
			a.port = req.Port() // the client named its own address: hold it to it
		}
	}
	associations.Lock()
	associations.byKey[key] = append(associations.byKey[key], a)
	associations.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			associations.Lock()
			defer associations.Unlock()
			list := associations.byKey[key]
			for i, it := range list {
				if it == a {
					list = append(list[:i:i], list[i+1:]...)
					break
				}
			}
			if len(list) == 0 {
				delete(associations.byKey, key)
			} else {
				associations.byKey[key] = list
			}
		})
	}
}

// lookupAssociation finds the association a datagram that arrived on local
// from remote belongs to, and returns its user. A datagram from a port no
// association holds yet claims the oldest association that has none.
func lookupAssociation(local, remote net.Addr) (user string, ok bool) {
	key, remoteAddr, ok := newAssociationKey(local, remote)
	if !ok {
		return "", false
	}
	port := remoteAddr.Port()
	associations.Lock()
	defer associations.Unlock()
	var free *association
	for _, a := range associations.byKey[key] {
		if a.port == port {
			return a.user, true
		}
		if a.port == 0 && free == nil {
			free = a
		}
	}
	if free == nil || port == 0 {
		return "", false
	}
	free.port = port
	return free.user, true
}

// hasAssociation reports whether any association is open for the client IP
// of remote on local.
func hasAssociation(local, remote net.Addr) bool {
	key, _, ok := newAssociationKey(local, remote)
	if !ok {
		return false
	}
	associations.Lock()
	defer associations.Unlock()
	return len(associations.byKey[key]) > 0
}
