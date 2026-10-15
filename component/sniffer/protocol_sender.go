package sniffer

import (
	"sync"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// PacketVerdict decides whether a packet of a UDP session tagged by a protocol
// sniffer has to be dropped. It is handed a copy of the packet's metadata with
// SniffProtocol set, and reports true when the rules send that metadata to
// REJECT. Dropping is all a NAT session can do: its outbound was chosen by
// its first packet and cannot be switched per destination.
type PacketVerdict func(metadata *C.Metadata) (drop bool)

const (
	// udpProtocolSniffPackets is how many packets to each new destination of
	// a session are inspected before that destination is considered clean.
	// A uTP connection opens with ST_SYN, a DHT exchange with a query, a
	// tracker exchange with a connect request, all of them first in line.
	udpProtocolSniffPackets = 8
	// udpProtocolMaxDestinations bounds the per-session state. A BitTorrent
	// client talks to thousands of peers and DHT nodes from one socket.
	udpProtocolMaxDestinations = 4096
)

// protocolPacketSender extends protocol sniffing beyond the first packet of a
// UDP NAT session.
//
// A NAT session is keyed by the source address only and its rule is matched
// once, against the first packet. A BitTorrent client sends its DHT, tracker
// and uTP traffic to thousands of destinations from one socket, so whatever
// the first packet looked like decided for all of them: a first packet to a
// destination the sniffer did not recognise let the rest of the swarm through.
//
// This sender inspects the first udpProtocolSniffPackets packets to every new
// destination. Once one of them is recognised, the whole session carries that
// protocol, since it is one application socket, and every destination of it
// is matched against the rules again with SniffProtocol set, once per
// destination. Packets to destinations that resolve to REJECT are dropped.
type protocolPacketSender struct {
	C.PacketSender
	sd      *Dispatcher
	verdict PacketVerdict

	mu sync.Mutex
	// protocol the session was recognised as, empty until then
	protocol string
	// packets inspected per destination while the protocol is unknown
	inspected map[string]uint8
	// drop decisions per destination once the protocol is known
	decisions map[string]bool
}

func newProtocolPacketSender(sd *Dispatcher, sender C.PacketSender, verdict PacketVerdict, first *C.Metadata) *protocolPacketSender {
	s := &protocolPacketSender{
		PacketSender: sender,
		sd:           sd,
		verdict:      verdict,
		protocol:     first.SniffProtocol,
	}
	// The first packet was inspected by UDPSniff and the session's own rule,
	// matched with whatever it found, already decides for its destination.
	if s.protocol == "" {
		s.inspected = map[string]uint8{first.RemoteAddress(): 1}
	} else {
		s.decisions = map[string]bool{first.RemoteAddress(): false}
	}
	return s
}

func (s *protocolPacketSender) Send(packet C.PacketAdapter) {
	if s.shouldDrop(packet) {
		packet.Drop()
		return
	}
	s.PacketSender.Send(packet)
}

func (s *protocolPacketSender) shouldDrop(packet C.PacketAdapter) bool {
	metadata := packet.Metadata()
	if s.sd.skipAddress(metadata) {
		return false
	}
	dst := metadata.RemoteAddress()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.protocol == "" {
		count, seen := s.inspected[dst]
		if count >= udpProtocolSniffPackets || (!seen && len(s.inspected) >= udpProtocolMaxDestinations) {
			return false
		}
		s.inspected[dst] = count + 1

		protocol := s.sd.packetProtocol(packet.Data(), metadata)
		if protocol == "" {
			return false
		}
		log.Debugln("[Sniffer] Sniff UDP [%s]-->[%s] as protocol [%s], tagging the session",
			metadata.SourceDetail(), metadata.RemoteAddress(), protocol)
		s.protocol = protocol
		s.sd.rememberSource(metadata, protocol)
		s.inspected = nil
		// destinations seen so far are matched again too, the decision taken
		// for the first one did not know the protocol
		s.decisions = make(map[string]bool)
	}

	drop, decided := s.decisions[dst]
	if !decided {
		tagged := metadata.Clone()
		tagged.SniffProtocol = s.protocol
		drop = s.verdict(tagged)
		if len(s.decisions) >= udpProtocolMaxDestinations {
			s.decisions = make(map[string]bool)
		}
		s.decisions[dst] = drop
	}
	return drop
}
