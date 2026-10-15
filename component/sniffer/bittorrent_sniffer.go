package sniffer

// The three detectors below are ported and modified from
// https://github.com/SagerNet/sing-box/blob/f2bbf6b2aaafd10ab7a6ca52e790732a4bcf447f/common/sniff/bittorrent.go
// which is licensed under the GNU General Public License v3.0 or later, with an
// additional term declining to grant the right to use the name of that project
// or to imply association with it.
// Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/sniffer"
)

var errNotBitTorrent = errors.New("not BitTorrent")

const (
	// btHandshakeHeader is the fixed prefix of the BitTorrent handshake message,
	// a length byte followed by the protocol identifier. See
	// https://www.bittorrent.org/beps/bep_0003.html
	btHandshakeHeader = "\x13BitTorrent protocol"

	// magic constants of the UDP tracker protocol
	// https://www.bittorrent.org/beps/bep_0015.html
	trackerProtocolID     = 0x41727101980
	trackerActionConnect  = 0
	trackerConnectMinSize = 16
)

// bitTorrentServerFirstPorts are the well-known ports of protocols in which the
// server speaks first. The client sends nothing until it has heard the server,
// so sniffing them can only wait for the TCP timeout and then give up. They
// are left out of the default port range; listing them in ports explicitly
// still sniffs them.
var bitTorrentServerFirstPorts = []uint16{
	21,   // FTP
	22,   // SSH
	23,   // Telnet
	25,   // SMTP
	110,  // POP3
	119,  // NNTP
	143,  // IMAP
	587,  // SMTP submission
	3306, // MySQL
	5900, // VNC
}

// bitTorrentDefaultPorts is 1-65535 without bitTorrentServerFirstPorts
func bitTorrentDefaultPorts() utils.IntRanges[uint16] {
	var ports utils.IntRanges[uint16]
	start := uint16(1)
	for _, port := range bitTorrentServerFirstPorts {
		if port > start {
			ports = append(ports, utils.NewRange[uint16](start, port-1))
		}
		start = port + 1
	}
	return append(ports, utils.NewRange[uint16](start, 65535))
}

var _ sniffer.ProtocolSniffer = (*BitTorrentSniffer)(nil)

type BitTorrentSniffer struct {
	*BaseSniffer
}

func NewBitTorrentSniffer(snifferConfig SnifferConfig) (*BitTorrentSniffer, error) {
	ports := snifferConfig.Ports
	if len(ports) == 0 {
		// BitTorrent peers listen on arbitrary ports, so there is no sensible
		// port whitelist to default to
		ports = bitTorrentDefaultPorts()
	}
	return &BitTorrentSniffer{
		BaseSniffer: NewBaseSniffer(ports, C.ALLNet),
	}, nil
}

func (bt *BitTorrentSniffer) Protocol() string {
	return "bittorrent"
}

func (bt *BitTorrentSniffer) SupportNetwork() C.NetWork {
	return C.ALLNet
}

// SniffData implements sniffer.Sniffer. BitTorrent traffic carries no domain,
// so this sniffer is only usable through SniffProtocol.
func (bt *BitTorrentSniffer) SniffData(bytes []byte) (string, error) {
	return "", errNotBitTorrent
}

func (bt *BitTorrentSniffer) SniffProtocol(network C.NetWork, b []byte) (string, error) {
	switch network {
	case C.TCP:
		if err := SniffBitTorrentHandshake(b); err != nil {
			return "", err
		}
	case C.UDP:
		if isWireGuard(b) {
			return "", errNotBitTorrent
		}
		if SniffUTP(b) != nil && SniffUDPTracker(b) != nil && SniffDHT(b) != nil {
			return "", errNotBitTorrent
		}
	default:
		return "", errNotBitTorrent
	}
	return C.ProtocolBitTorrent, nil
}

// SniffBitTorrentHandshake detects the handshake that opens every BitTorrent
// peer connection. See https://www.bittorrent.org/beps/bep_0003.html
func SniffBitTorrentHandshake(b []byte) error {
	if len(b) < len(btHandshakeHeader) {
		// only ask for more data while what arrived so far still matches,
		// otherwise this is definitely something else
		if !strings.HasPrefix(btHandshakeHeader, string(b)) {
			return errNotBitTorrent
		}
		return &errNeedAtLeastData{
			length: len(btHandshakeHeader),
			err:    ErrNoClue,
		}
	}

	if string(b[:len(btHandshakeHeader)]) != btHandshakeHeader {
		return errNotBitTorrent
	}
	return nil
}

// uTP packet types and the protocol version, see
// https://www.bittorrent.org/beps/bep_0029.html
const (
	utpHeaderSize = 20
	utpVersion    = 1
	utpStSyn      = 4

	// extension types defined by libutp: selective ack and extension bits
	utpExtSelectiveAck = 1
	utpExtBits         = 2
)

// SniffUTP detects the packet that opens a uTP connection, the transport
// BitTorrent peers use over UDP. See https://www.bittorrent.org/beps/bep_0029.html and
// https://github.com/bittorrent/libutp/blob/2b364cbb0650bdab64a5de2abb4518f9f228ec44/utp_internal.cpp#L112
//
// Only ST_SYN is accepted. A uTP header has no magic: the generic check
// (version 1, type 0-4, a well formed extension chain) lets one random datagram
// in a few hundred thousand through, and a WireGuard handshake initiation
// (01 00 00 00, 148 bytes) passes it outright, since it reads as ST_DATA
// without extensions. The dispatcher inspects the first packets sent to every
// new destination, and the first packet of an outgoing uTP connection is
// always ST_SYN, so nothing is lost by insisting on it. ST_SYN carries no
// payload, so the extension chain must end exactly at the end of the
// datagram, which is what makes random data fail.
func SniffUTP(b []byte) error {
	if len(b) < utpHeaderSize {
		return errNotBitTorrent
	}
	if b[0] != utpStSyn<<4|utpVersion {
		return errNotBitTorrent
	}
	// the sender has not heard from the peer yet, so there is no delay sample
	// to echo back (libutp and libtorrent both start from zero)
	if binary.BigEndian.Uint32(b[8:12]) != 0 {
		return errNotBitTorrent
	}
	// a peer that advertises a zero receive window cannot be opening a connection
	if binary.BigEndian.Uint32(b[12:16]) == 0 {
		return errNotBitTorrent
	}

	// walk the extension chain: the header names the first extension, then
	// every link is the type of the next one, a length byte and that many
	// bytes, terminated by a zero type
	extension := b[1]
	rest := b[utpHeaderSize:]
	for extension != 0 {
		if len(rest) < 2 {
			return errNotBitTorrent
		}
		length := int(rest[1])
		switch extension {
		case utpExtSelectiveAck:
			// a bitmask of at least 32 bits, in whole 32 bit words
			if length < 4 || length%4 != 0 {
				return errNotBitTorrent
			}
		case utpExtBits:
			if length != 8 {
				return errNotBitTorrent
			}
		default:
			return errNotBitTorrent
		}
		if length > len(rest)-2 {
			return errNotBitTorrent
		}
		extension = rest[0]
		rest = rest[2+length:]
	}
	// ST_SYN carries no payload
	if len(rest) != 0 {
		return errNotBitTorrent
	}

	return nil
}

// WireGuard message types and their fixed sizes, see
// https://www.wireguard.com/protocol/
const (
	wgHandshakeInitiation = 1
	wgHandshakeResponse   = 2
	wgCookieReply         = 3
	wgTransportData       = 4

	wgHandshakeInitiationSize = 148
	wgHandshakeResponseSize   = 92
	wgCookieReplySize         = 64
	wgTransportDataMinSize    = 32 // header and the authentication tag of an empty keepalive
)

// isWireGuard reports whether b has the shape of a WireGuard message: a type
// byte of 1 to 4, three reserved zero bytes and the length fixed for that type.
// UDP detectors rule these out first, so a WireGuard tunnel is never taken for
// BitTorrent whatever the detectors below accept.
func isWireGuard(b []byte) bool {
	if len(b) < 4 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return false
	}
	switch b[0] {
	case wgHandshakeInitiation:
		return len(b) == wgHandshakeInitiationSize
	case wgHandshakeResponse:
		return len(b) == wgHandshakeResponseSize
	case wgCookieReply:
		return len(b) == wgCookieReplySize
	case wgTransportData:
		// the encrypted payload is padded to a multiple of 16 bytes
		return len(b) >= wgTransportDataMinSize && (len(b)-wgTransportDataMinSize)%16 == 0
	}
	return false
}

// SniffUDPTracker detects the connect request of the UDP tracker protocol.
// See https://www.bittorrent.org/beps/bep_0015.html
func SniffUDPTracker(b []byte) error {
	if len(b) < trackerConnectMinSize {
		return errNotBitTorrent
	}
	if binary.BigEndian.Uint64(b[:8]) != trackerProtocolID {
		return errNotBitTorrent
	}
	if binary.BigEndian.Uint32(b[8:12]) != trackerActionConnect {
		return errNotBitTorrent
	}
	return nil
}

// KRPC limits: the deepest message (a get_peers response holding a list of
// peer strings) nests three levels, and a DHT datagram fits one MTU
const (
	dhtMaxDepth   = 8
	dhtNodeIDSize = 20
)

// SniffDHT detects a message of the BitTorrent DHT, a KRPC query, response or
// error. See https://www.bittorrent.org/beps/bep_0005.html and
// https://www.bittorrent.org/beps/bep_0042.html
//
// The datagram must be exactly one well formed bencoded dictionary whose "y"
// is "q", "r" or "e": a query carries "q" and an argument dictionary "a" with
// a 20 byte "id", a response a dictionary "r" with a 20 byte "id", an error a
// list "e". Keys are sorted in bencode, so in practice queries start with
// "d1:ad2:id20:", responses with "d1:rd2:id20:" or, with the BEP 42 "ip" key,
// "d2:ip6:", and errors with "d1:eli", but the full parse is what decides.
func SniffDHT(b []byte) error {
	if len(b) < 2 || b[0] != 'd' || b[len(b)-1] != 'e' {
		return errNotBitTorrent
	}
	// the cheap prefix check keeps the parser away from almost everything
	// that is not KRPC
	if !bytes.HasPrefix(b, []byte("d1:a")) && !bytes.HasPrefix(b, []byte("d1:r")) &&
		!bytes.HasPrefix(b, []byte("d1:e")) && !bytes.HasPrefix(b, []byte("d2:ip")) {
		return errNotBitTorrent
	}

	fields, end, ok := bencodeDict(b, 0, 0)
	if !ok || end != len(b) {
		return errNotBitTorrent
	}
	if _, ok := bencodeString(fields["t"]); !ok {
		return errNotBitTorrent
	}
	y, ok := bencodeString(fields["y"])
	if !ok {
		return errNotBitTorrent
	}
	switch y {
	case "q":
		if q, ok := bencodeString(fields["q"]); !ok || q == "" {
			return errNotBitTorrent
		}
		if !dhtHasNodeID(fields["a"]) {
			return errNotBitTorrent
		}
	case "r":
		if !dhtHasNodeID(fields["r"]) {
			return errNotBitTorrent
		}
	case "e":
		if e := fields["e"]; len(e) == 0 || e[0] != 'l' {
			return errNotBitTorrent
		}
	default:
		return errNotBitTorrent
	}
	return nil
}

// dhtHasNodeID reports whether raw is a dictionary holding the 20 byte node
// id every query and response carries
func dhtHasNodeID(raw []byte) bool {
	if len(raw) == 0 || raw[0] != 'd' {
		return false
	}
	fields, _, ok := bencodeDict(raw, 0, 0)
	if !ok {
		return false
	}
	id, ok := bencodeString(fields["id"])
	return ok && len(id) == dhtNodeIDSize
}

// bencodeDict parses the dictionary at b[pos] and returns its entries as raw
// bencoded values along with the offset past it. Keys must be byte strings.
func bencodeDict(b []byte, pos, depth int) (map[string][]byte, int, bool) {
	if depth > dhtMaxDepth || pos >= len(b) || b[pos] != 'd' {
		return nil, 0, false
	}
	fields := make(map[string][]byte)
	pos++
	for pos < len(b) && b[pos] != 'e' {
		key, next, ok := bencodeStringAt(b, pos)
		if !ok {
			return nil, 0, false
		}
		end, ok := bencodeSkip(b, next, depth+1)
		if !ok {
			return nil, 0, false
		}
		fields[key] = b[next:end]
		pos = end
	}
	if pos >= len(b) {
		return nil, 0, false
	}
	return fields, pos + 1, true
}

// bencodeSkip returns the offset past the bencoded value at b[pos]
func bencodeSkip(b []byte, pos, depth int) (int, bool) {
	if depth > dhtMaxDepth || pos >= len(b) {
		return 0, false
	}
	switch c := b[pos]; {
	case c == 'i':
		pos++
		if pos < len(b) && b[pos] == '-' {
			pos++
		}
		start := pos
		for pos < len(b) && b[pos] >= '0' && b[pos] <= '9' {
			pos++
		}
		if pos == start || pos >= len(b) || b[pos] != 'e' {
			return 0, false
		}
		return pos + 1, true
	case c == 'l' || c == 'd':
		pos++
		for pos < len(b) && b[pos] != 'e' {
			if c == 'd' {
				_, next, ok := bencodeStringAt(b, pos)
				if !ok {
					return 0, false
				}
				pos = next
			}
			next, ok := bencodeSkip(b, pos, depth+1)
			if !ok {
				return 0, false
			}
			pos = next
		}
		if pos >= len(b) {
			return 0, false
		}
		return pos + 1, true
	case c >= '0' && c <= '9':
		_, next, ok := bencodeStringAt(b, pos)
		return next, ok
	}
	return 0, false
}

// bencodeStringAt parses the byte string at b[pos] and returns it along with
// the offset past it
func bencodeStringAt(b []byte, pos int) (string, int, bool) {
	length := 0
	start := pos
	for pos < len(b) && b[pos] >= '0' && b[pos] <= '9' {
		length = length*10 + int(b[pos]-'0')
		if length > len(b) {
			return "", 0, false
		}
		pos++
	}
	if pos == start || pos >= len(b) || b[pos] != ':' {
		return "", 0, false
	}
	pos++
	if length > len(b)-pos {
		return "", 0, false
	}
	return string(b[pos : pos+length]), pos + length, true
}

// bencodeString decodes raw as a whole byte string
func bencodeString(raw []byte) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	s, end, ok := bencodeStringAt(raw, 0)
	return s, ok && end == len(raw)
}
