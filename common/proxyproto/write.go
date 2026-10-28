package proxyproto

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
)

// Append appends h, as a header of h.Version (1 or 2), to b: what a front end
// puts in front of a connection it forwards, for the server behind it to read
// with Read.
//
// A Local header is the v2 LOCAL command (v1 has none: "PROXY UNKNOWN"). A
// header whose Source or Destination is not valid, the client address of a
// forwarded connection that is unknown (a unix socket), is the PROXY command
// with no address (v2 AF_UNSPEC, v1 UNKNOWN): the server keeps its peer
// address either way. An IPv4 pair is sent as TCP4, IPv4-mapped addresses
// unmapped; a pair with an IPv6 address as TCP6, the IPv4 one mapped. Zones
// are dropped.
func (h Header) Append(b []byte) ([]byte, error) {
	src, dst := h.Source.Addr().Unmap().WithZone(""), h.Destination.Addr().Unmap().WithZone("")
	known := !h.Local && h.Source.IsValid() && h.Destination.IsValid()
	inet := known && src.Is4() && dst.Is4()
	if known && !inet {
		src, dst = netip.AddrFrom16(src.As16()), netip.AddrFrom16(dst.As16())
	}
	switch h.Version {
	case 1:
		if !known {
			return append(b, "PROXY UNKNOWN\r\n"...), nil
		}
		b = append(b, "PROXY TCP6 "...)
		if inet {
			b[len(b)-2] = '4'
		}
		b = src.AppendTo(b)
		b = append(b, ' ')
		b = dst.AppendTo(b)
		b = append(b, ' ')
		b = strconv.AppendUint(b, uint64(h.Source.Port()), 10)
		b = append(b, ' ')
		b = strconv.AppendUint(b, uint64(h.Destination.Port()), 10)
		return append(b, '\r', '\n'), nil
	case 2:
		b = append(b, v2Signature...)
		switch {
		case h.Local:
			return append(b, 0x20, v2FamilyUnspec<<4, 0, 0), nil
		case !known:
			return append(b, 0x21, v2FamilyUnspec<<4, 0, 0), nil
		}
		family, size := byte(v2FamilyInet6), 16
		if inet {
			family, size = v2FamilyInet, 4
		}
		b = append(b, 0x21, family<<4|v2ProtoStream)
		b = binary.BigEndian.AppendUint16(b, uint16(2*size+4))
		b = append(b, src.AsSlice()...)
		b = append(b, dst.AsSlice()...)
		b = binary.BigEndian.AppendUint16(b, h.Source.Port())
		return binary.BigEndian.AppendUint16(b, h.Destination.Port()), nil
	}
	return b, fmt.Errorf("proxy protocol: version %d", h.Version)
}
