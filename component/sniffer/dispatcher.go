package sniffer

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/metacubex/sing/common/metadata"

	"github.com/metacubex/mihomo/common/lru"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/sniffer"
	"github.com/metacubex/mihomo/log"
)

var (
	ErrorUnsupportedSniffer = errors.New("unsupported sniffer")
	ErrorSniffFailed        = errors.New("all sniffer failed")
	ErrNoClue               = errors.New("not enough information for making a decision")
)

// maxSniffBufferSize bounds the per-connection read-ahead memory used by TCP
// sniffing. 64 KiB covers the HTTP/2 preface and several default-sized frames
// while keeping lengths read from untrusted protocol headers bounded.
const maxSniffBufferSize = 64 * 1024

type Dispatcher struct {
	enable bool
	// sniffers recover the domain a connection is heading to, protocolSniffers
	// only tag it with the application protocol and never touch the destination
	sniffers         []configuredSniffer
	protocolSniffers []sniffer.ProtocolSniffer
	forceDomain      []C.DomainMatcher
	skipSrcAddress   []C.IpMatcher
	skipDstAddress   []C.IpMatcher
	skipDomain       []C.DomainMatcher
	skipList         *lru.LruCache[netip.AddrPort, uint8]
	// taggedSources remembers the UDP sockets protocol sniffers recognised,
	// see rememberSource
	taggedSources   *lru.LruCache[netip.AddrPort, string]
	forceDnsMapping bool
	parsePureIp     bool
	// skipThreshold is how many failed sniffs a destination may collect in
	// skipList before it is no longer sniffed, negative = never skip
	skipThreshold int
}

// configuredSniffer keeps protocol-specific behavior and policy together so
// the successful sniffer's policy is applied to its result.
type configuredSniffer struct {
	sniffer.Sniffer
	config SnifferConfig
}

func (s configuredSniffer) supportsNetwork(network C.NetWork) bool {
	return snifferSupportsNetwork(s, network)
}

func snifferSupportsNetwork(s sniffer.Sniffer, network C.NetWork) bool {
	supported := s.SupportNetwork()
	return supported == network || supported == C.ALLNet
}

// skipAddress reports whether skip-src-address or skip-dst-address exempt the
// connection from sniffing, domain and protocol sniffers alike
func (sd *Dispatcher) skipAddress(metadata *C.Metadata) bool {
	for _, matcher := range sd.skipDstAddress {
		if matcher.MatchIp(metadata.DstIP) {
			return true
		}
	}
	return sd.skipSource(metadata)
}

// shouldOverride reports whether a domain should be sniffed for the connection
func (sd *Dispatcher) shouldOverride(metadata *C.Metadata) bool {
	if sd.skipAddress(metadata) {
		return false
	}
	if metadata.Host == "" && sd.parsePureIp {
		return true
	}
	if metadata.DNSMode == C.DNSMapping && sd.forceDnsMapping {
		return true
	}
	return sd.forceSniff(metadata)
}

func (sd *Dispatcher) forceSniff(metadata *C.Metadata) bool {
	for _, matcher := range sd.forceDomain {
		if matcher.MatchDomain(metadata.Host) {
			return true
		}
	}
	return false
}

// hasProtocolSniffer reports whether a protocol sniffer covers the network and
// destination port
func (sd *Dispatcher) hasProtocolSniffer(network C.NetWork, port uint16) bool {
	for _, current := range sd.protocolSniffers {
		if snifferSupportsNetwork(current, network) && current.SupportPort(port) {
			return true
		}
	}
	return false
}

// UDPSniff is called when a UDP NAT is created and passed the first initialization packet.
// It may return a wrapped packetSender if the sniffer process needs to wait for multiple packets.
// This function must be non-blocking, and any blocking operations should be done in the wrapped packetSender.
//
// Protocol sniffers run whatever the destination looks like: they never touch
// it, so the parse-pure-ip, force-dns-mapping and force-domain conditions that
// decide whether a domain is worth recovering do not apply to them. Only
// skip-src-address and skip-dst-address exempt a session.
//
// When verdict is not nil and a protocol sniffer covers UDP, the returned
// sender keeps inspecting the first packets to every further destination of
// the session and drops what verdict rejects, see protocolPacketSender.
func (sd *Dispatcher) UDPSniff(packet C.PacketAdapter, packetSender C.PacketSender, verdict PacketVerdict) C.PacketSender {
	metadata := packet.Metadata()
	if !sd.skipAddress(metadata) {
		if protocol := sd.packetProtocol(packet.Data(), metadata); protocol != "" {
			log.Debugln("[Sniffer] Sniff UDP [%s]-->[%s] as protocol [%s]",
				metadata.SourceDetail(), metadata.RemoteAddress(), protocol)
			metadata.SniffProtocol = protocol
			sd.rememberSource(metadata, protocol)
		} else if protocol, ok := sd.taggedSources.Get(sourceOf(metadata)); ok {
			log.Debugln("[Sniffer] UDP [%s]-->[%s] comes from a socket sniffed as protocol [%s]",
				metadata.SourceDetail(), metadata.RemoteAddress(), protocol)
			metadata.SniffProtocol = protocol
		}
		if sd.shouldOverride(metadata) {
			packetSender = sd.udpSniffDomain(packet, packetSender)
		}
	}

	// skip-src-address exempts the whole session, skip-dst-address is checked
	// for every packet by the wrapper
	if verdict != nil && sd.hasUDPProtocolSniffer() && !sd.skipSource(metadata) {
		packetSender = newProtocolPacketSender(sd, packetSender, verdict, metadata)
	}
	return packetSender
}

const (
	taggedSourcesSize = 1024
	// seconds; refreshed whenever a new session from the socket inherits it
	taggedSourcesAge = 300
)

// rememberSource records that the UDP socket metadata comes from carries
// protocol. A NAT session that its rules reject is torn down at once, and the
// next packet from the same socket opens a fresh session. Without this the
// fresh session would start untagged, and since only the first packets of a
// BitTorrent exchange are recognisable, its rule would let the rest of the
// exchange through. New sessions from a remembered socket inherit the tag.
func (sd *Dispatcher) rememberSource(metadata *C.Metadata, protocol string) {
	sd.taggedSources.Set(sourceOf(metadata), protocol)
}

func sourceOf(metadata *C.Metadata) netip.AddrPort {
	return netip.AddrPortFrom(metadata.SrcIP.Unmap(), metadata.SrcPort)
}

func (sd *Dispatcher) skipSource(metadata *C.Metadata) bool {
	for _, matcher := range sd.skipSrcAddress {
		if matcher.MatchIp(metadata.SrcIP) {
			return true
		}
	}
	return false
}

func (sd *Dispatcher) hasUDPProtocolSniffer() bool {
	for _, current := range sd.protocolSniffers {
		if snifferSupportsNetwork(current, C.UDP) {
			return true
		}
	}
	return false
}

func (sd *Dispatcher) udpSniffDomain(packet C.PacketAdapter, packetSender C.PacketSender) C.PacketSender {
	metadata := packet.Metadata()
	for _, current := range sd.sniffers {
		if current.supportsNetwork(C.UDP) {
			inWhitelist := current.SupportPort(metadata.DstPort)
			overrideDest := current.config.OverrideDest

			if inWhitelist {
				replaceDomain := func(metadata *C.Metadata, host string) {
					if sd.domainCanReplace(host) {
						replaceDomain(metadata, host, overrideDest)
					} else {
						log.Debugln("[Sniffer] Skip sni[%s]", host)
					}
				}

				if wrapable, ok := current.Sniffer.(sniffer.MultiPacketSniffer); ok {
					return wrapable.WrapperSender(packetSender, replaceDomain)
				}

				host, err := current.SniffData(packet.Data())
				if err != nil {
					continue
				}

				replaceDomain(metadata, host)
				return packetSender
			}
		}
	}
	return packetSender
}

// TCPSniff returns true if the connection is sniffed to have a domain.
//
// As with UDPSniff, protocol sniffers run whenever skip-src-address and
// skip-dst-address allow, independently of whether a domain is sniffed.
func (sd *Dispatcher) TCPSniff(conn *N.BufferedConn, metadata *C.Metadata) bool {
	if sd.skipAddress(metadata) {
		return false
	}

	sniffed, waited := false, false
	if sd.shouldOverride(metadata) {
		sniffed, waited = sd.tcpSniffDomain(conn, metadata)
	}

	// Protocol sniffers report no domain, so their outcome does not feed the
	// result. When domain sniffing already waited for the client and nothing
	// came, waiting again would only delay a server-first connection further.
	if sd.hasProtocolSniffer(C.TCP, metadata.DstPort) && !(waited && conn.Buffered() == 0) {
		sd.sniffStreamProtocol(conn, metadata)
	}
	return sniffed
}

// tcpSniffDomain recovers the domain of a TCP connection. waited reports
// whether it read from the connection, successfully or not.
func (sd *Dispatcher) tcpSniffDomain(conn *N.BufferedConn, metadata *C.Metadata) (sniffed bool, waited bool) {
	inWhitelist := false
	for _, current := range sd.sniffers {
		if current.supportsNetwork(C.TCP) {
			inWhitelist = current.SupportPort(metadata.DstPort)
			if inWhitelist {
				break
			}
		}
	}

	if !inWhitelist {
		return false, false
	}
	forceSniffer := sd.forceSniff(metadata)

	dst := metadata.AddrPort()
	if !forceSniffer && sd.skipFailed(dst) {
		log.Debugln("[Sniffer] Skip sniffing[%s] due to multiple failures", dst)
		return false, false
	}

	host, config, err := sd.sniffDomain(conn, metadata)
	if err != nil {
		if !forceSniffer {
			sd.cacheSniffFailed(metadata)
		}
		log.Debugln("[Sniffer] All sniffing sniff failed with from [%s:%d] to [%s:%d]", metadata.SrcIP, metadata.SrcPort, metadata.String(), metadata.DstPort)
		return false, true
	}

	if !sd.domainCanReplace(host) {
		log.Debugln("[Sniffer] Skip sni[%s]", host)
		return false, true
	}

	sd.skipList.Delete(dst)

	replaceDomain(metadata, host, config.OverrideDest)
	return true, true
}

func replaceDomain(metadata *C.Metadata, host string, overrideDest bool) {
	metadata.SniffHost = host
	if overrideDest {
		log.Debugln("[Sniffer] Sniff %s [%s]-->[%s] success, replace domain [%s]-->[%s]",
			metadata.NetWork,
			metadata.SourceDetail(),
			metadata.RemoteAddress(),
			metadata.Host, host)
		metadata.Host = host
		metadata.DstIP = netip.Addr{}
	}
	metadata.DNSMode = C.DNSNormal
}

func (sd *Dispatcher) domainCanReplace(host string) bool {
	if !isValidSniffHost(host) {
		return false
	}
	for _, matcher := range sd.skipDomain {
		if matcher.MatchDomain(host) {
			return false
		}
	}
	return true
}

func isValidSniffHost(host string) bool {
	return host != "." && metadata.IsDomainName(host)
}

func (sd *Dispatcher) Enable() bool {
	return sd != nil && sd.enable
}

func (sd *Dispatcher) sniffDomain(conn *N.BufferedConn, metadata *C.Metadata) (string, SnifferConfig, error) {
	//defer func(start time.Time) {
	//	log.Debugln("[Sniffer] [%s] Sniffing took %s", metadata.DstIP, time.Since(start))
	//}(time.Now())

	type candidate struct {
		configuredSniffer
		want int // minimum buffer length required before the next attempt
	}
	// Keep the configured order while discarding protocols that cannot apply to
	// this connection. The remaining entries carry their own OverrideDest policy.
	candidates := make([]candidate, 0, len(sd.sniffers))
	for _, current := range sd.sniffers {
		if current.supportsNetwork(C.TCP) && current.SupportPort(metadata.DstPort) {
			candidates = append(candidates, candidate{configuredSniffer: current, want: 1})
		}
	}
	if len(candidates) == 0 {
		return "", SnifferConfig{}, ErrorSniffFailed
	}

	// The initial byte has its own one-second window because client data may not
	// have arrived yet. Peek usually buffers the whole available segment.
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, err := conn.Peek(1)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		// The caller owns failure accounting and the connection lifetime. No
		// initial data can be valid for a server-first protocol, so sniffing must
		// not close the connection merely because this deadline expired.
		log.Debugln("[Sniffer] [%s] the data length not enough, error: %v", metadata.DstIP, err)
		return "", SnifferConfig{}, err
	}

	// After the initial read, all candidates and retries share a fresh budget.
	deadline := time.Now().Add(1 * time.Second)
	want := conn.Buffered()
	for len(candidates) > 0 {
		// Reject an unmet oversized request before Grow or Peek. Otherwise Peek
		// fills the bounded buffer before reporting that the request cannot fit.
		if want > maxSniffBufferSize && want > conn.Buffered() {
			return "", SnifferConfig{}, bufio.ErrBufferFull
		}
		conn.Grow(want)

		_ = conn.SetReadDeadline(deadline)
		_, err = conn.Peek(want)
		_ = conn.SetReadDeadline(time.Time{})
		if err != nil {
			// Initial data was received, so leave the connection open for the caller
			// to continue relaying without a sniffed domain.
			log.Debugln("[Sniffer] [%s] the data length not enough, error: %v", metadata.DstIP, err)
			return "", SnifferConfig{}, err
		}

		// The first Peek may buffer more than requested. Everything reported by
		// Buffered is already available, so this second Peek cannot read or fail.
		data, _ := conn.Peek(conn.Buffered())

		// Compact the active set in place. A candidate remains active only while
		// it has a larger input requirement; permanent failures and
		// invalid successful results are discarded.
		remaining := candidates[:0]
		nextWant := 0
		for _, current := range candidates {
			// Another candidate may have requested the shorter read that produced
			// this snapshot. Leave larger requests paused until enough data exists.
			if current.want <= len(data) {
				host, err := current.SniffData(data)
				if err == nil {
					if isValidSniffHost(host) {
						return host, current.config, nil
					}
					continue
				}

				// Only an explicit request beyond this snapshot can make progress in
				// another round. All other errors permanently reject the candidate.
				var need *errNeedAtLeastData
				if !errors.As(err, &need) || need.length <= len(data) {
					continue
				}
				current.want = need.length
			}

			remaining = append(remaining, current)
			if nextWant == 0 || current.want < nextWant {
				nextWant = current.want
			}
		}

		candidates = remaining
		want = nextWant
	}

	return "", SnifferConfig{}, ErrorSniffFailed
}

// protocolSniffTimeout bounds how long protocol sniffing waits for a TCP
// client. Unlike domain sniffing it runs on every port by default, including
// those of protocols where the server speaks first and the client sends
// nothing, so it must give up quickly. Every protocol it detects is client
// first, the BitTorrent handshake is written as soon as the connection is up,
// and on the local side of TUN or a local proxy that is well under this bound.
const protocolSniffTimeout = 300 * time.Millisecond

// sniffStreamProtocol tags the metadata with the application protocol of a TCP
// connection. Unlike a domain, nothing downstream depends on the result, so a
// miss is neither reported to the caller nor counted towards skipList, and a
// client that has sent nothing within protocolSniffTimeout is let through
// untagged.
func (sd *Dispatcher) sniffStreamProtocol(conn *N.BufferedConn, metadata *C.Metadata) {
	// When domain sniffing ran first, the data is already buffered.
	deadline := time.Now().Add(protocolSniffTimeout)
	if conn.Buffered() == 0 {
		_ = conn.SetReadDeadline(deadline)
		_, err := conn.Peek(1)
		_ = conn.SetReadDeadline(time.Time{})
		if err != nil {
			log.Debugln("[Sniffer] [%s] no data for protocol sniffing, error: %v", metadata.DstIP, err)
			return
		}
		// the rest of a header split across segments gets a fresh window
		deadline = time.Now().Add(protocolSniffTimeout)
	}

	for _, current := range sd.protocolSniffers {
		if !snifferSupportsNetwork(current, C.TCP) || !current.SupportPort(metadata.DstPort) {
			continue
		}

		data, _ := conn.Peek(conn.Buffered())
		protocol, err := current.SniffProtocol(C.TCP, data)

		// Protocol signatures sit in a fixed-size header, so one refill is
		// enough. Requests beyond the read-ahead bound are rejected outright.
		var need *errNeedAtLeastData
		if errors.As(err, &need) && need.length > len(data) && need.length <= maxSniffBufferSize {
			conn.Grow(need.length)
			_ = conn.SetReadDeadline(deadline)
			_, err = conn.Peek(need.length)
			_ = conn.SetReadDeadline(time.Time{})
			if err != nil {
				continue
			}
			data, _ = conn.Peek(conn.Buffered())
			protocol, err = current.SniffProtocol(C.TCP, data)
		}
		if err != nil {
			continue
		}

		log.Debugln("[Sniffer] Sniff TCP [%s]-->[%s] as protocol [%s]",
			metadata.SourceDetail(), metadata.RemoteAddress(), protocol)
		metadata.SniffProtocol = protocol
		return
	}
}

// packetProtocol returns the application protocol carried by a UDP packet,
// or an empty string
func (sd *Dispatcher) packetProtocol(data []byte, metadata *C.Metadata) string {
	for _, current := range sd.protocolSniffers {
		if !snifferSupportsNetwork(current, C.UDP) || !current.SupportPort(metadata.DstPort) {
			continue
		}
		if protocol, err := current.SniffProtocol(C.UDP, data); err == nil {
			return protocol
		}
	}
	return ""
}

// skipFailed reports whether sniffing dst failed more than skipThreshold times
func (sd *Dispatcher) skipFailed(dst netip.AddrPort) bool {
	if sd.skipThreshold < 0 {
		return false
	}
	count, ok := sd.skipList.Get(dst)
	return ok && int(count) > sd.skipThreshold
}

func (sd *Dispatcher) cacheSniffFailed(metadata *C.Metadata) {
	if sd.skipThreshold < 0 {
		return
	}
	dst := metadata.AddrPort()
	sd.skipList.Compute(dst, func(oldValue uint8, loaded bool) (newValue uint8, delete bool) {
		// one past the threshold is enough to skip, and keeps the counter in uint8
		if int(oldValue) <= sd.skipThreshold {
			oldValue++
		}
		return oldValue, false
	})
}

const (
	// DefaultSkipThreshold is the skip-threshold used when none is configured
	DefaultSkipThreshold = 5
	// MaxSkipThreshold is the largest skip-threshold the uint8 failure counter can hold
	MaxSkipThreshold = math.MaxUint8 - 1
)

type Config struct {
	Enable          bool
	Sniffers        map[sniffer.Type]SnifferConfig
	ForceDomain     []C.DomainMatcher
	SkipSrcAddress  []C.IpMatcher
	SkipDstAddress  []C.IpMatcher
	SkipDomain      []C.DomainMatcher
	ForceDnsMapping bool
	ParsePureIp     bool
	// SkipThreshold: a destination stops being sniffed for a while once more
	// than this many sniffs to it failed. nil = DefaultSkipThreshold,
	// negative = never skip.
	SkipThreshold *int
}

func NewDispatcher(snifferConfig *Config) (*Dispatcher, error) {
	skipThreshold := DefaultSkipThreshold
	if snifferConfig.SkipThreshold != nil {
		skipThreshold = *snifferConfig.SkipThreshold
	}
	if skipThreshold > MaxSkipThreshold {
		return &Dispatcher{enable: false}, fmt.Errorf("skip-threshold %d is above %d", skipThreshold, MaxSkipThreshold)
	}

	dispatcher := Dispatcher{
		enable:         snifferConfig.Enable,
		forceDomain:    snifferConfig.ForceDomain,
		skipSrcAddress: snifferConfig.SkipSrcAddress,
		skipDstAddress: snifferConfig.SkipDstAddress,
		skipDomain:     snifferConfig.SkipDomain,
		skipList:       lru.New(lru.WithSize[netip.AddrPort, uint8](128), lru.WithAge[netip.AddrPort, uint8](600)),
		taggedSources: lru.New(
			lru.WithSize[netip.AddrPort, string](taggedSourcesSize),
			lru.WithAge[netip.AddrPort, string](taggedSourcesAge),
			lru.WithUpdateAgeOnGet[netip.AddrPort, string](),
		),
		forceDnsMapping: snifferConfig.ForceDnsMapping,
		parsePureIp:     snifferConfig.ParsePureIp,
		skipThreshold:   skipThreshold,
		sniffers:        make([]configuredSniffer, 0, len(snifferConfig.Sniffers)),
	}

	// Configuration is map-based, but protocol order must remain deterministic
	// when multiple sniffers cover the same port.
	for _, snifferName := range sniffer.List {
		config, loaded := snifferConfig.Sniffers[snifferName]
		if !loaded {
			continue
		}
		s, err := NewSniffer(snifferName, config)
		if err != nil {
			log.Errorln("Sniffer name[%s] is error", snifferName)
			return &Dispatcher{enable: false}, err
		}
		// A protocol sniffer carries no domain, so it stays out of the domain
		// candidate set and out of the OverrideDest policy that comes with it.
		if ps, ok := s.(sniffer.ProtocolSniffer); ok {
			dispatcher.protocolSniffers = append(dispatcher.protocolSniffers, ps)
			continue
		}
		dispatcher.sniffers = append(dispatcher.sniffers, configuredSniffer{Sniffer: s, config: config})
	}
	// Entries absent from sniffer.List were not constructed by the ordered pass
	// above. Preserve the previous behavior of rejecting such configurations.
	if len(dispatcher.sniffers)+len(dispatcher.protocolSniffers) != len(snifferConfig.Sniffers) {
		for snifferName := range snifferConfig.Sniffers {
			found := false
			for _, supported := range sniffer.List {
				if snifferName == supported {
					found = true
					break
				}
			}
			if !found {
				log.Errorln("Sniffer name[%s] is error", snifferName)
				return &Dispatcher{enable: false}, ErrorUnsupportedSniffer
			}
		}
	}

	return &dispatcher, nil
}

func NewSniffer(name sniffer.Type, snifferConfig SnifferConfig) (sniffer.Sniffer, error) {
	switch name {
	case sniffer.TLS:
		return NewTLSSniffer(snifferConfig)
	case sniffer.HTTP:
		return NewHTTPSniffer(snifferConfig)
	case sniffer.QUIC:
		return NewQUICSniffer(snifferConfig)
	case sniffer.BitTorrent:
		return NewBitTorrentSniffer(snifferConfig)
	default:
		return nil, ErrorUnsupportedSniffer
	}
}
