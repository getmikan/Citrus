package outbound

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/egress"
	"github.com/metacubex/mihomo/component/loopback"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/Nemu-x/desync"
)

// Bounds of the options given in milliseconds. The library accepts longer
// values; a configuration that needs them is almost certainly a mistake.
const (
	desyncMaxSplitDelay       = time.Second
	desyncMaxFakeTimeout      = time.Minute
	desyncMaxSplitWaitTimeout = time.Minute
)

// The library's defaults, shown in the API.
const (
	desyncDefaultFakeTimeout      = 3 * time.Second
	desyncDefaultSplitWaitTimeout = 2 * time.Second
)

// desyncCaps is what the library implements on this OS. Validation takes it
// as a parameter, so that the per-OS errors can be tested on any OS.
var desyncCaps = desync.PlatformCapabilities()

// desyncConditional reports whether the library implements method on this OS
// but decides per socket whether a connection can use it (Android, where
// unsent bytes are read from TCP_INFO when the kernel provides them). Such a
// method is listed in Unsupported too; configuration accepts it, and a socket
// that cannot honor it fails the first write before any byte is sent.
func desyncConditional(caps desync.Capabilities, method string) bool {
	_, ok := caps.Conditional[method]
	return ok
}

// DesyncOption is the configuration of a "desync" outbound: a DIRECT
// connection whose first TLS ClientHello is transformed by
// github.com/Nemu-x/desync. Everything after the ClientHello, and any
// connection that does not start with one, passes through unchanged.
type DesyncOption struct {
	BasicOption
	Name string `proxy:"name"`
	// TLSRec and Split are comma-separated positions: "3" is byte 3 of the
	// TLS wire input, "1+s" one byte after the start of the server name.
	TLSRec     string `proxy:"tlsrec,omitempty"`
	Split      string `proxy:"split,omitempty"`
	SplitDelay int    `proxy:"split-delay,omitempty"` // milliseconds between split writes
	// SplitWait is "sent" or "acked": before each further split piece, wait
	// until the kernel reports the earlier bytes as transmitted or
	// acknowledged. It is never replaced by a timed pause.
	SplitWait        string `proxy:"split-wait,omitempty"`
	SplitWaitTimeout int    `proxy:"split-wait-timeout,omitempty"` // milliseconds per wait; 0 = 2 s
	// Disorder sends the first split piece with hop limit 1 (ByeDPI --disorder).
	Disorder bool `proxy:"disorder,omitempty"`
	// OOB sends one urgent byte after the first split piece (ByeDPI --oob).
	OOB     bool                `proxy:"oob,omitempty"`
	OOBByte string              `proxy:"oob-byte,omitempty"` // one character; empty = "a"
	Random  *DesyncRandomOption `proxy:"random,omitempty"`
	Fake    *DesyncFakeOption   `proxy:"fake,omitempty"`
	UDP     *DesyncUDPOption    `proxy:"udp,omitempty"`
}

// DesyncRandomOption adds random record and write cuts, drawn per
// connection, to the fixed tlsrec and split positions.
type DesyncRandomOption struct {
	TLSRec []DesyncRandomCut `proxy:"tlsrec,omitempty"`
	Split  []DesyncRandomCut `proxy:"split,omitempty"`
	Seed   uint64            `proxy:"seed,omitempty"` // 0 = a new seed per connection
}

// DesyncRandomCut draws count cuts from the inclusive range from..to, both
// positions absolute or both relative to the server name ("+s"), at least
// min-piece bytes apart.
type DesyncRandomCut struct {
	From     string `proxy:"from"`
	To       string `proxy:"to"`
	Count    int    `proxy:"count,omitempty"`     // 0 = 1
	MinPiece int    `proxy:"min-piece,omitempty"` // 0 = 1
}

// DesyncFakeOption sends a low-TTL decoy as the first transmission of the
// ClientHello prefix, or of the split piece that ends at the prefix.
// Windows, Linux and Android.
type DesyncFakeOption struct {
	TTL     int                  `proxy:"ttl,omitempty"` // with auto-ttl the fallback; 0 = none
	AutoTTL *DesyncAutoTTLOption `proxy:"auto-ttl,omitempty"`
	Prefix  int                  `proxy:"prefix,omitempty"`  // after record fragmentation; negative counts from the end, 0 = -1
	Timeout int                  `proxy:"timeout,omitempty"` // milliseconds for the native send; 0 = library default (3 s)
	// Decoy ClientHello: another server name (one drawn per connection;
	// '*', '?' and '#' are random), fresh random values, built from the
	// connection's own hello, started at a later byte.
	SNI          []string `proxy:"sni,omitempty"`
	Randomize    bool     `proxy:"randomize,omitempty"`
	FromOriginal bool     `proxy:"from-original,omitempty"`
	Offset       int      `proxy:"offset,omitempty"`
}

// DesyncAutoTTLOption derives the fake's TTL from the server's SYN-ACK:
// hops - delta, clamped to min..max. Zero fields are the defaults 1, 3, 20.
type DesyncAutoTTLOption struct {
	Delta int `proxy:"delta,omitempty"`
	Min   int `proxy:"min,omitempty"`
	Max   int `proxy:"max,omitempty"`
}

// DesyncUDPOption sends a bounded burst of low-TTL datagrams before the first
// datagrams to each peer. Without it UDP is plain DIRECT.
type DesyncUDPOption struct {
	TTL      int    `proxy:"ttl"`
	Repeats  int    `proxy:"repeats,omitempty"`   // 0 = 6
	Packets  int    `proxy:"packets,omitempty"`   // 0 = 3
	Template string `proxy:"template,omitempty"`  // zero (64 zero bytes, default) or quic (a QUIC v1 Initial)
	SNI      string `proxy:"sni,omitempty"`       // server name of the quic template
	QUICOnly bool   `proxy:"quic-only,omitempty"` // burst only before datagrams that look like a QUIC Initial
}

// desyncStrategy picks the TCP transformation of one connection. Options is
// called on every dial, so it must answer from configuration or a cache and
// never run discovery itself. The only implementation today is the static,
// explicitly configured one; a strategy controller can take its place later
// without touching the dial path.
type desyncStrategy interface {
	Options(metadata *C.Metadata) desync.Options
	String() string
}

type staticDesyncStrategy struct{ opts desync.Options }

func (s staticDesyncStrategy) Options(*C.Metadata) desync.Options { return s.opts }

func (s staticDesyncStrategy) String() string { return "static" }

// Desync is a DIRECT outbound that applies a desync transformation to its
// connections. It reuses Direct for name resolution, loopback detection and
// the plain UDP path, and owns the TCP dial so that the transformer is in
// place before the first byte is written.
type Desync struct {
	*Direct
	strategy desyncStrategy
	tcp      desync.Options     // the configured options, for the API
	udp      *desync.UDPOptions // nil: UDP is plain DIRECT
	// lastFakeTTL is the TTL of the latest fake, with desyncAutoTTLFlag when
	// auto-ttl derived it; 0 until a fake was sent.
	lastFakeTTL atomic.Int32
}

const desyncAutoTTLFlag = 1 << 8

// DialContext implements C.ProxyAdapter
func (d *Desync) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := d.loopBack.CheckConn(metadata); err != nil {
		return nil, err
	}
	tcpOpts := d.strategy.Options(metadata)
	opts := d.DialOptions()
	opts = append(opts, dialer.WithResolver(resolver.DirectHostResolver))
	if guard := egress.For(metadata); guard != nil {
		// as DIRECT: checked on the resolved addresses right before the connect
		opts = append(opts, dialer.WithAddrFilter(guard))
	}
	autoTTL := tcpOpts.Fake != nil && tcpOpts.Fake.AutoTTL != nil
	if autoTTL {
		// Before connect, so that the TTL of the SYN-ACK is recorded
		// (Linux/Android IPv6; a no-op elsewhere). The dialer chains the
		// interface, routing mark and socket hook controls after it.
		opts = append(opts, dialer.WithNetDialer(&net.Dialer{Control: desync.ControlAutoTTL}))
	}
	c, err := dialer.DialContext(ctx, "tcp", directAddress(metadata), opts...)
	if err != nil {
		return nil, err
	}
	if !tcpOpts.Enabled() {
		return d.loopBack.NewConn(NewConn(c, d)), nil
	}
	dc := &desyncConn{Conn: desync.WrapConn(c, tcpOpts), socket: c}
	if tcpOpts.Fake != nil {
		dc.lastFakeTTL, dc.autoTTL = &d.lastFakeTTL, autoTTL
	}
	return d.loopBack.NewConn(newDesyncConn(dc, d)), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (d *Desync) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if d.udp == nil {
		return d.Direct.ListenPacketContext(ctx, metadata)
	}
	if err := d.loopBack.CheckPacketConn(metadata); err != nil {
		return nil, err
	}
	if err := d.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	pc, err := dialer.NewDialer(d.DialOptions()...).ListenPacket(ctx, "udp", "", metadata.AddrPort())
	if err != nil {
		return nil, err
	}
	// The wrapper owns the socket for its whole lifetime: it changes the
	// hop limit around the fake datagrams, so nothing may write to the
	// socket beside it. Peer state lives with the socket and ends with it.
	wrapped, err := desync.WrapPacketConn(pc, *d.udp)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	var out net.PacketConn = &desyncPacketConn{wrapped}
	if guard := egress.For(metadata); guard != nil {
		// outside the wrapper, so a blocked peer gets no fake datagrams either
		out = egress.NewPacketConn(out, guard)
	}
	return d.loopBack.NewPacketConn(NewPacketConn(out, d)), nil
}

// MarshalJSON implements C.ProxyAdapter
func (d *Desync) MarshalJSON() ([]byte, error) {
	o := d.tcp
	tcp := map[string]any{
		"tlsrec":             desyncPositions(o.TLSRec),
		"split":              desyncPositions(o.Split),
		"split-delay":        o.SplitDelay.Milliseconds(),
		"split-wait":         o.SplitWait.String(),
		"split-wait-timeout": int64(0),
		"disorder":           o.Disorder,
		"oob":                nil,
		"random":             nil,
		"fake":               nil,
	}
	if o.SplitWait != desync.SplitWaitNone || o.Disorder {
		timeout := o.SplitWaitTimeout
		if timeout == 0 {
			timeout = desyncDefaultSplitWaitTimeout
		}
		tcp["split-wait-timeout"] = timeout.Milliseconds()
	}
	if o.OOB != nil {
		b := o.OOB.Byte
		if b == 0 {
			b = desync.DefaultOOBByte
		}
		tcp["oob"] = map[string]any{"byte": string(rune(b))}
	}
	if r := o.Random; r != nil {
		tcp["random"] = map[string]any{
			"tlsrec": desyncRandomCuts(r.TLSRec),
			"split":  desyncRandomCuts(r.Split),
			"seed":   r.Seed,
		}
	}
	if fake := o.Fake; fake != nil {
		timeout := fake.Timeout
		if timeout == 0 {
			timeout = desyncDefaultFakeTimeout
		}
		info := map[string]any{
			"ttl":           fake.TTL,
			"auto-ttl":      nil,
			"prefix":        fake.Prefix,
			"timeout":       timeout.Milliseconds(),
			"sni":           append([]string{}, fake.SNI...),
			"randomize":     fake.Randomize,
			"from-original": fake.FromOriginal,
			"offset":        fake.Offset,
			"last-ttl":      nil,
		}
		if a := fake.AutoTTL; a != nil {
			info["auto-ttl"] = map[string]any{"delta": a.Delta, "min": a.Min, "max": a.Max}
		}
		if v := d.lastFakeTTL.Load(); v != 0 {
			info["last-ttl"] = map[string]any{"ttl": v &^ desyncAutoTTLFlag, "auto": v&desyncAutoTTLFlag != 0}
		}
		tcp["fake"] = info
	}
	var udp any
	if u := d.udp; u != nil {
		template := "zero"
		if u.Template == desync.UDPTemplateQUICInitial {
			template = "quic"
		}
		udp = map[string]any{
			"ttl":       u.TTL,
			"repeats":   u.Repeats,
			"packets":   u.Packets,
			"template":  template,
			"sni":       u.SNI,
			"quic-only": u.QUICOnly,
			"counters":  u.Counters.Snapshot(),
		}
	}
	// One key of its own: Proxy.MarshalJSON adds "udp" and others next to it.
	return json.Marshal(map[string]any{
		"type": d.Type().String(),
		"id":   d.Id(),
		"desync": map[string]any{
			"strategy": d.strategy.String(),
			"tcp":      tcp,
			"udp":      udp,
		},
	})
}

func desyncPositions(positions []desync.Pos) []string {
	out := make([]string, 0, len(positions))
	for _, p := range positions {
		out = append(out, p.String())
	}
	return out
}

func desyncRandomCuts(cuts []desync.RandomCut) []map[string]any {
	out := make([]map[string]any, 0, len(cuts))
	for _, c := range cuts {
		out = append(out, map[string]any{
			"from":      c.From.String(),
			"to":        c.To.String(),
			"count":     max(c.Count, 1),
			"min-piece": max(c.MinPiece, 1),
		})
	}
	return out
}

func parseDesyncPositions(text string) ([]desync.Pos, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	var positions []desync.Pos
	for _, part := range strings.Split(text, ",") {
		p, err := desync.ParsePos(part)
		if err != nil {
			return nil, err
		}
		positions = append(positions, p)
	}
	return positions, nil
}

func desyncMilliseconds(name string, ms int, limit time.Duration) (time.Duration, error) {
	d := time.Duration(ms) * time.Millisecond
	if ms < 0 || d > limit {
		return 0, fmt.Errorf("%s must be between 0 and %d ms", name, limit.Milliseconds())
	}
	return d, nil
}

// desyncUnsupported is the configuration error for a method that the
// library does not implement on this OS, with the library's reason.
func desyncUnsupported(caps desync.Capabilities, option, method string, sentinel error) error {
	reason := caps.Unsupported[method]
	if reason == "" {
		reason = "not implemented"
	}
	return fmt.Errorf("%s is not supported on %s (%s): %w", option, caps.OS, reason, sentinel)
}

func parseDesyncRandomCuts(name string, cuts []DesyncRandomCut) ([]desync.RandomCut, error) {
	var out []desync.RandomCut
	for i, c := range cuts {
		from, err := desync.ParsePos(c.From)
		if err != nil {
			return nil, fmt.Errorf("random %s[%d] from: %w", name, i, err)
		}
		to, err := desync.ParsePos(c.To)
		if err != nil {
			return nil, fmt.Errorf("random %s[%d] to: %w", name, i, err)
		}
		if c.Count < 0 || c.MinPiece < 0 {
			return nil, fmt.Errorf("random %s[%d]: count and min-piece must not be negative", name, i)
		}
		out = append(out, desync.RandomCut{From: from, To: to, Count: c.Count, MinPiece: c.MinPiece})
	}
	return out, nil
}

func (o DesyncOption) tcpOptions(caps desync.Capabilities) (opts desync.Options, err error) {
	// Methods accepted although this OS decides them per socket.
	var conditional []string
	if opts.TLSRec, err = parseDesyncPositions(o.TLSRec); err != nil {
		return opts, fmt.Errorf("tlsrec: %w", err)
	}
	if opts.Split, err = parseDesyncPositions(o.Split); err != nil {
		return opts, fmt.Errorf("split: %w", err)
	}
	if r := o.Random; r != nil {
		opts.Random = &desync.RandomOptions{Seed: r.Seed}
		if opts.Random.TLSRec, err = parseDesyncRandomCuts("tlsrec", r.TLSRec); err != nil {
			return opts, err
		}
		if opts.Random.Split, err = parseDesyncRandomCuts("split", r.Split); err != nil {
			return opts, err
		}
		if len(opts.Random.TLSRec) == 0 && len(opts.Random.Split) == 0 {
			return opts, errors.New("random needs tlsrec or split ranges")
		}
	}
	splits := len(opts.Split) > 0 || opts.Random != nil && len(opts.Random.Split) > 0
	if opts.SplitDelay, err = desyncMilliseconds("split-delay", o.SplitDelay, desyncMaxSplitDelay); err != nil {
		return opts, err
	}
	if opts.SplitDelay > 0 && !splits {
		return opts, errors.New("split-delay needs split positions")
	}

	if opts.SplitWait, err = desync.ParseSplitWait(o.SplitWait); err != nil {
		return opts, fmt.Errorf(`split-wait must be "sent" or "acked", not %q`, o.SplitWait)
	}
	if opts.SplitWaitTimeout, err = desyncMilliseconds("split-wait-timeout", o.SplitWaitTimeout, desyncMaxSplitWaitTimeout); err != nil {
		return opts, err
	}
	if opts.SplitWaitTimeout > 0 && opts.SplitWait == desync.SplitWaitNone && !o.Disorder {
		return opts, errors.New("split-wait-timeout needs split-wait or disorder")
	}
	if opts.SplitWait != desync.SplitWaitNone {
		if !splits {
			return opts, errors.New("split-wait needs split positions")
		}
		if opts.SplitWait == desync.SplitWaitSent && !caps.Ack.Sent && desyncConditional(caps, "split-wait-sent") {
			conditional = append(conditional, "split-wait sent")
		} else if !caps.Ack.Supports(opts.SplitWait) {
			return opts, fmt.Errorf("split-wait %s is not supported on %s (%s): %w",
				opts.SplitWait, caps.OS, desyncAckReason(caps.Ack), desync.ErrSplitWaitUnsupported)
		}
	}

	opts.Disorder = o.Disorder
	if o.Disorder {
		if !splits {
			return opts, errors.New("disorder needs split positions: it acts on the first split piece")
		}
		if !caps.Disorder.Supported && desyncConditional(caps, "disorder") {
			conditional = append(conditional, "disorder")
		} else if !caps.Disorder.Supported {
			return opts, desyncUnsupported(caps, "disorder", "disorder", desync.ErrDisorderUnsupported)
		}
	}
	if o.OOBByte != "" && !o.OOB {
		return opts, errors.New("oob-byte needs oob")
	}
	if o.OOB {
		if !splits {
			return opts, errors.New("oob needs split positions: the urgent byte follows the first split piece")
		}
		if !caps.OOB {
			return opts, desyncUnsupported(caps, "oob", "oob", desync.ErrOOBUnsupported)
		}
		opts.OOB = &desync.OOBOptions{}
		if o.OOBByte != "" {
			if len(o.OOBByte) != 1 || o.OOBByte[0] == 0 || o.OOBByte[0] > 0x7f {
				return opts, fmt.Errorf("oob-byte must be one ASCII character, not %q", o.OOBByte)
			}
			opts.OOB.Byte = o.OOBByte[0]
		}
	}

	if f := o.Fake; f != nil {
		if !caps.FakeTCP && desyncConditional(caps, "fake-tcp") {
			conditional = append(conditional, "fake")
		} else if !caps.FakeTCP {
			return opts, desyncUnsupported(caps, "fake", "fake-tcp", desync.ErrFakeUnsupported)
		}
		if f.AutoTTL == nil && f.TTL == 0 {
			return opts, errors.New("fake needs ttl (1-255) or auto-ttl")
		}
		timeout, err := desyncMilliseconds("fake timeout", f.Timeout, desyncMaxFakeTimeout)
		if err != nil {
			return opts, err
		}
		opts.Fake = &desync.FakeOptions{
			TTL:          f.TTL,
			Prefix:       f.Prefix,
			Timeout:      timeout,
			SNI:          f.SNI,
			Randomize:    f.Randomize,
			FromOriginal: f.FromOriginal,
			Offset:       f.Offset,
		}
		if a := f.AutoTTL; a != nil {
			auto := desync.AutoTTL{Delta: a.Delta, Min: a.Min, Max: a.Max}
			if err := auto.Validate(); err != nil {
				return opts, fmt.Errorf("fake auto-ttl: %w", err)
			}
			// The library's defaults, filled in here so that the API shows them.
			auto.Delta, auto.Min, auto.Max = cmp.Or(auto.Delta, 1), cmp.Or(auto.Min, 3), cmp.Or(auto.Max, 20)
			opts.Fake.AutoTTL = &auto
			if err := o.checkAutoTTL(caps); err != nil {
				return opts, err
			}
		}
	}
	if err := opts.Validate(); err != nil {
		return opts, err
	}
	if len(conditional) > 0 {
		log.Infoln("[desync] %s: %s on %s is verified per connection: a socket that cannot observe its unsent bytes fails the connection before anything is sent",
			o.Name, strings.Join(conditional, ", "), caps.OS)
	}
	return opts, nil
}

// checkAutoTTL rejects an auto-ttl that can never derive a TTL here and has
// no fallback ttl, and logs where it falls back for one address family.
func (o DesyncOption) checkAutoTTL(caps desync.Capabilities) error {
	ttl := o.Fake.TTL
	v4, v6 := caps.AutoTTL.IPv4, caps.AutoTTL.IPv6
	switch o.IPVersion {
	case C.IPv4Only:
		v6 = false
	case C.IPv6Only:
		v4 = false
	}
	if !v4 && !v6 {
		reason := caps.Unsupported["auto-ttl-ipv4"]
		if o.IPVersion == C.IPv6Only || reason == "" {
			reason = caps.Unsupported["auto-ttl-ipv6"]
		}
		if ttl == 0 {
			return fmt.Errorf("fake auto-ttl cannot observe the path on %s (%s); set ttl as the fallback: %w",
				caps.OS, reason, desync.ErrAutoTTLUnsupported)
		}
		log.Warnln("[desync] %s: auto-ttl cannot observe the path on %s (%s); every fake uses ttl %d",
			o.Name, caps.OS, reason, ttl)
		return nil
	}
	if !v4 && o.IPVersion != C.IPv6Only {
		if ttl == 0 {
			log.Warnln("[desync] %s: auto-ttl observes only IPv6 on %s (%s); IPv4 connections fail without a fallback ttl",
				o.Name, caps.OS, caps.Unsupported["auto-ttl-ipv4"])
		} else {
			log.Infoln("[desync] %s: auto-ttl observes only IPv6 on %s; IPv4 connections use ttl %d", o.Name, caps.OS, ttl)
		}
	}
	return nil
}

// desyncAckReason says which split-wait modes this OS can observe.
func desyncAckReason(a desync.AckCapability) string {
	if a.Mechanism == "" {
		return "the send queue cannot be observed"
	}
	var modes []string
	for _, m := range []desync.SplitWait{desync.SplitWaitSent, desync.SplitWaitAcked} {
		if a.Supports(m) {
			modes = append(modes, m.String())
		}
	}
	return fmt.Sprintf("%s observes only %s", a.Mechanism, strings.Join(modes, ", "))
}

func (o DesyncOption) udpOptions(caps desync.Capabilities) (*desync.UDPOptions, error) {
	u := o.UDP
	if u == nil {
		return nil, nil
	}
	if !caps.FakeUDP {
		return nil, desyncUnsupported(caps, "udp", "fake-udp", desync.ErrUDPFakeUnsupported)
	}
	opts := desync.UDPOptions{TTL: u.TTL, Repeats: u.Repeats, Packets: u.Packets, SNI: u.SNI, QUICOnly: u.QUICOnly}
	switch u.Template {
	case "", "zero":
	case "quic":
		opts.Template = desync.UDPTemplateQUICInitial
	default:
		return nil, fmt.Errorf(`udp template must be "zero" or "quic", not %q`, u.Template)
	}
	if opts.SNI != "" && opts.Template != desync.UDPTemplateQUICInitial {
		return nil, errors.New("udp sni needs template: quic")
	}
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	// The library's defaults, filled in here so that the API shows them.
	opts.Repeats = cmp.Or(opts.Repeats, 6)
	opts.Packets = cmp.Or(opts.Packets, 3)
	if opts.Template == desync.UDPTemplateQUICInitial && opts.SNI == "" {
		opts.SNI = desync.DefaultQUICSNI
	}
	opts.Counters = &desync.UDPCounters{} // shared by all sockets of the outbound
	return &opts, nil
}

// NewDesync validates the options; anything the platform or the library
// cannot do is a configuration error, never a silent plain DIRECT.
func NewDesync(option DesyncOption) (*Desync, error) {
	d, err := newDesync(option, desyncCaps)
	if err != nil {
		return nil, fmt.Errorf("desync %q: %w", option.Name, err)
	}
	return d, nil
}

func newDesync(option DesyncOption, caps desync.Capabilities) (*Desync, error) {
	// TFO sends the first write with the SYN, before the transformer could
	// cut it; MPTCP spreads it over subflows that no longer match the cuts,
	// and the socket methods (fake, disorder, oob, split-wait, auto-ttl)
	// need a plain TCP socket.
	if option.TFO {
		return nil, errors.New("tfo is not supported: the ClientHello would leave with the SYN")
	}
	if option.MPTCP {
		return nil, errors.New("mptcp is not supported")
	}
	if option.DialerProxy != "" {
		return nil, errors.New("dialer-proxy is not supported: desync dials directly")
	}
	tcp, err := option.tcpOptions(caps)
	if err != nil {
		return nil, err
	}
	udp, err := option.udpOptions(caps)
	if err != nil {
		return nil, err
	}
	if !tcp.Enabled() && udp == nil {
		return nil, errors.New("set at least one of tlsrec, split, random, fake or udp")
	}
	return &Desync{
		Direct: &Direct{
			Base: NewBase(BaseOption{
				Name:         option.Name,
				Type:         C.Desync,
				ProviderName: option.ProviderName,
				UDP:          true,
				Interface:    option.Interface,
				RoutingMark:  option.RoutingMark,
				Prefer:       option.IPVersion,
			}),
			loopBack: loopback.NewDetector(),
		},
		strategy: staticDesyncStrategy{tcp},
		tcp:      tcp,
		udp:      udp,
	}, nil
}

// desyncConn is the transformed side of a desync TCP connection.
//
// The transformer must see the ClientHello, so no relay fast path may write
// to the socket underneath it: desyncConn exposes neither the socket
// (NetConn, Upstream, SyscallConn: splice, sendfile, writev batching) nor a
// replaceable writer. It stays on the write path for the whole connection,
// not just the ClientHello: the native fake may still own the socket after
// the hello was accepted, and an extra copy of the upload is cheap next to a
// bypass. Reads are untouched by desync, so the reader is replaceable and the
// relay reads the socket directly (splice of the download on Linux).
type desyncConn struct {
	net.Conn          // *desync.Conn
	socket   net.Conn // the dialed socket, for reading only

	// With a fake: where to report the TTL it was sent with, and whether
	// the socket records received hop limits for auto-ttl.
	lastFakeTTL *atomic.Int32
	autoTTL     bool
	reported    atomic.Bool
	written     atomic.Bool
}

func newDesyncConn(dc *desyncConn, a C.ProxyAdapter) C.Conn {
	// Not NewConn: the deadline wrapper it adds for outbound conns is not
	// needed (deadlines go to the socket) and would hide the raw reader.
	cc := &conn{ExtendedConn: N.NewExtendedConn(dc), adapterAddr: a.Addr()}
	cc.AppendToChains(a)
	return cc
}

func (c *desyncConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if c.lastFakeTTL != nil && len(p) > 0 && !c.reported.Load() {
		c.reportFake(p)
	}
	return n, err
}

// reportFake publishes the TTL the connection's fake was sent with. A
// connection whose first write is not a TLS handshake record gets no fake:
// the hop limit recording that auto-ttl enabled is turned off then, as the
// transformer does once it read the value.
func (c *desyncConn) reportFake(p []byte) {
	if tc, ok := c.Conn.(*desync.Conn); ok {
		if ttl, auto := tc.FakeTTL(); ttl != 0 {
			v := int32(ttl)
			if auto {
				v |= desyncAutoTTLFlag
			}
			c.lastFakeTTL.Store(v)
			c.reported.Store(true)
			return
		}
	}
	if !c.written.Swap(true) && p[0] != 0x16 {
		c.reported.Store(true)
		if c.autoTTL {
			desyncStopHopRecording(c.socket)
		}
	}
}

// UpstreamReader implements network.WithUpstreamReader
func (c *desyncConn) UpstreamReader() any { return c.socket }

// ReaderReplaceable implements network.ReaderWithUpstream
func (c *desyncConn) ReaderReplaceable() bool { return true }

// CloseWrite half-closes the socket. A ClientHello still being assembled at
// that point is incomplete and is dropped, as it would be on Close.
func (c *desyncConn) CloseWrite() error {
	if cw, ok := c.socket.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// desyncPacketConn hides the *desync.PacketConn (and the socket under it)
// from upstream casts: every datagram has to go through its WriteTo.
type desyncPacketConn struct{ net.PacketConn }
