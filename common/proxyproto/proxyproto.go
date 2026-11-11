// Package proxyproto reads the PROXY protocol header (versions 1 and 2, see
// https://www.haproxy.org/download/3.0/doc/proxy-protocol.txt) that a TCP
// front end such as an SNI router, HAProxy or nginx puts in front of a
// forwarded connection, so that the listener behind it learns the address of
// the real client.
//
// The header is read byte-exact, with no read-ahead: whatever follows it is
// left in the connection, which stays a plain net.Conn for the protocol
// handshake. TCP only: nothing here touches UDP.
package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
)

var (
	// ErrNoHeader means the stream does not start with a PROXY protocol header.
	ErrNoHeader = errors.New("proxy protocol: no header")
	// ErrMalformed means the header is there but invalid or unsupported.
	ErrMalformed = errors.New("proxy protocol: malformed header")
	// ErrTooLong means the header is longer than the protocol allows (v1) or
	// than MaxV2Length (v2).
	ErrTooLong = errors.New("proxy protocol: header too long")
	// ErrTruncated means the stream ended inside the header.
	ErrTruncated = errors.New("proxy protocol: truncated header")
)

const (
	// maxV1Length is the longest v1 line, "\r\n" included.
	maxV1Length = 107
	// MaxV2Length is the longest v2 payload (addresses and TLVs) accepted. The
	// protocol allows 65535; the addresses take 36 bytes at most, the rest is
	// TLVs that are skipped, and no real front end sends kilobytes of them.
	MaxV2Length = 2048

	v2SigLength = 12
)

var (
	v2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")
	v1Signature = []byte("PROXY ")
)

// Header is a parsed PROXY protocol header.
type Header struct {
	// Version is 1 or 2.
	Version int
	// Local is true when the header carries no client address: the v2 LOCAL
	// command (a health check of the proxy itself), a v2 PROXY command with an
	// unspecified or unix address family, or a v1 UNKNOWN line. The connection
	// keeps the address of its TCP peer.
	Local bool
	// Source and Destination are the client and the server address the front
	// end saw, valid unless Local.
	Source, Destination netip.AddrPort
}

// Read reads one PROXY protocol header from r and leaves everything after it
// unread. A stream that starts with anything else gives ErrNoHeader; r must
// have a read deadline (or be closed by the caller), Read has none of its own.
func Read(r io.Reader) (Header, error) {
	var prefix [v2SigLength]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Header{}, ErrTruncated
		}
		return Header{}, err
	}
	switch {
	case bytes.Equal(prefix[:], v2Signature):
		return readV2(r)
	case bytes.HasPrefix(prefix[:], v1Signature):
		return readV1(r, prefix[:])
	}
	return Header{}, ErrNoHeader
}

// readV1 reads the rest of a v1 line, "PROXY TCP4 <src> <dst> <sport> <dport>\r\n",
// of which got is the start. The line is read a byte at a time: nothing past
// the "\n" may be consumed.
func readV1(r io.Reader, got []byte) (Header, error) {
	// a line shorter than the 12 bytes read for the signature has its end in
	// them, with stream data after it: no valid line is that short
	if i := bytes.IndexByte(got, '\n'); i >= 0 && i != len(got)-1 {
		return Header{}, fmt.Errorf("%w: v1 line shorter than its signature", ErrMalformed)
	}
	line := make([]byte, len(got), maxV1Length)
	copy(line, got)
	var b [1]byte
	for {
		if len(line) > 0 && line[len(line)-1] == '\n' {
			break
		}
		if len(line) == maxV1Length {
			return Header{}, ErrTooLong
		}
		if _, err := io.ReadFull(r, b[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return Header{}, ErrTruncated
			}
			return Header{}, err
		}
		line = append(line, b[0])
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return Header{}, fmt.Errorf("%w: v1 line does not end in CRLF", ErrMalformed)
	}
	fields := bytes.Split(line[:len(line)-2], []byte{' '})
	// fields[0] is "PROXY"
	if string(fields[1]) == "UNKNOWN" {
		// the rest of the line is ignored, as the protocol requires
		return Header{Version: 1, Local: true}, nil
	}
	if len(fields) != 6 {
		return Header{}, fmt.Errorf("%w: v1 line has %d fields", ErrMalformed, len(fields))
	}
	var want4 bool
	switch string(fields[1]) {
	case "TCP4":
		want4 = true
	case "TCP6":
	default:
		return Header{}, fmt.Errorf("%w: v1 protocol %q", ErrMalformed, fields[1])
	}
	src, err := parseV1Addr(fields[2], want4)
	if err != nil {
		return Header{}, err
	}
	dst, err := parseV1Addr(fields[3], want4)
	if err != nil {
		return Header{}, err
	}
	sport, err := parseV1Port(fields[4])
	if err != nil {
		return Header{}, err
	}
	dport, err := parseV1Port(fields[5])
	if err != nil {
		return Header{}, err
	}
	return Header{
		Version:     1,
		Source:      netip.AddrPortFrom(src, sport),
		Destination: netip.AddrPortFrom(dst, dport),
	}, nil
}

func parseV1Addr(field []byte, want4 bool) (netip.Addr, error) {
	addr, err := netip.ParseAddr(string(field))
	if err != nil || addr.Zone() != "" || addr.Is4() != want4 {
		return netip.Addr{}, fmt.Errorf("%w: v1 address %q", ErrMalformed, field)
	}
	return addr, nil
}

func parseV1Port(field []byte) (uint16, error) {
	port, err := strconv.ParseUint(string(field), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%w: v1 port %q", ErrMalformed, field)
	}
	return uint16(port), nil
}

// v2 address families and transport protocols (high and low nibble of byte 13).
const (
	v2FamilyUnspec = 0x0
	v2FamilyInet   = 0x1
	v2FamilyInet6  = 0x2
	v2FamilyUnix   = 0x3

	v2ProtoStream = 0x1
)

// readV2 reads a v2 header whose 12-byte signature is already consumed.
func readV2(r io.Reader) (Header, error) {
	var fixed [4]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Header{}, ErrTruncated
		}
		return Header{}, err
	}
	if fixed[0]>>4 != 2 {
		return Header{}, fmt.Errorf("%w: version %d", ErrMalformed, fixed[0]>>4)
	}
	command := fixed[0] & 0x0f
	family, proto := fixed[1]>>4, fixed[1]&0x0f
	length := int(binary.BigEndian.Uint16(fixed[2:]))
	if length > MaxV2Length {
		return Header{}, ErrTooLong
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Header{}, ErrTruncated
		}
		return Header{}, err
	}

	switch command {
	case 0x0: // LOCAL: the payload is ignored, the peer address stays
		return Header{Version: 2, Local: true}, nil
	case 0x1: // PROXY
	default:
		return Header{}, fmt.Errorf("%w: command %d", ErrMalformed, command)
	}

	switch family {
	case v2FamilyUnspec, v2FamilyUnix:
		// no IP to take over: keep the peer address
		return Header{Version: 2, Local: true}, nil
	case v2FamilyInet, v2FamilyInet6:
	default:
		return Header{}, fmt.Errorf("%w: address family %d", ErrMalformed, family)
	}
	if proto != v2ProtoStream {
		// UDP (or nothing) over a TCP listener is a front end bug
		return Header{}, fmt.Errorf("%w: transport protocol %d on a TCP stream", ErrMalformed, proto)
	}

	size := 4
	if family == v2FamilyInet6 {
		size = 16
	}
	if len(payload) < 2*size+4 {
		return Header{}, fmt.Errorf("%w: address block of %d bytes, need %d", ErrMalformed, len(payload), 2*size+4)
	}
	// anything after the addresses is TLVs, skipped
	src, _ := netip.AddrFromSlice(payload[:size])
	dst, _ := netip.AddrFromSlice(payload[size : 2*size])
	ports := payload[2*size:]
	return Header{
		Version:     2,
		Source:      netip.AddrPortFrom(src, binary.BigEndian.Uint16(ports)),
		Destination: netip.AddrPortFrom(dst, binary.BigEndian.Uint16(ports[2:])),
	}, nil
}
