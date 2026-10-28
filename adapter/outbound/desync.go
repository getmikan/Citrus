package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/loopback"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	"github.com/Nemu-x/desync"
)

// Bounds of the options given in milliseconds. The library accepts longer
// values; a configuration that needs them is almost certainly a mistake.
const (
	desyncMaxSplitDelay  = time.Second
	desyncMaxFakeTimeout = time.Minute
)

// DesyncOption is the configuration of a "desync" outbound: a DIRECT
// connection whose first TLS ClientHello is transformed by
// github.com/Nemu-x/desync. Everything after the ClientHello, and any
// connection that does not start with one, passes through unchanged.
type DesyncOption struct {
	BasicOption
	Name string `proxy:"name"`
	// TLSRec and Split are comma-separated positions: "3" is byte 3 of the
	// TLS wire input, "1+s" one byte after the start of the server name.
	TLSRec     string            `proxy:"tlsrec,omitempty"`
	Split      string            `proxy:"split,omitempty"`
	SplitDelay int               `proxy:"split-delay,omitempty"` // milliseconds between split writes
	Fake       *DesyncFakeOption `proxy:"fake,omitempty"`
	UDP        *DesyncUDPOption  `proxy:"udp,omitempty"`
}

// DesyncFakeOption sends a low-TTL alternate prefix before the ClientHello.
// Windows only.
type DesyncFakeOption struct {
	TTL     int `proxy:"ttl"`
	Prefix  int `proxy:"prefix,omitempty"`  // after record fragmentation; negative counts from the end, 0 = -1
	Timeout int `proxy:"timeout,omitempty"` // milliseconds for the native send; 0 = library default (3 s)
}

// DesyncUDPOption sends a bounded burst of low-TTL datagrams before the first
// datagrams to each peer. Windows only; without it UDP is plain DIRECT.
type DesyncUDPOption struct {
	TTL     int `proxy:"ttl"`
	Repeats int `proxy:"repeats,omitempty"` // 0 = 6
	Packets int `proxy:"packets,omitempty"` // 0 = 3
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
}

// DialContext implements C.ProxyAdapter
func (d *Desync) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := d.loopBack.CheckConn(metadata); err != nil {
		return nil, err
	}
	opts := d.DialOptions()
	opts = append(opts, dialer.WithResolver(resolver.DirectHostResolver))
	c, err := dialer.DialContext(ctx, "tcp", directAddress(metadata), opts...)
	if err != nil {
		return nil, err
	}
	tcpOpts := d.strategy.Options(metadata)
	if !tcpOpts.Enabled() {
		return d.loopBack.NewConn(NewConn(c, d)), nil
	}
	return d.loopBack.NewConn(newDesyncConn(c, desync.WrapConn(c, tcpOpts), d)), nil
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
	return d.loopBack.NewPacketConn(NewPacketConn(&desyncPacketConn{wrapped}, d)), nil
}

// MarshalJSON implements C.ProxyAdapter
func (d *Desync) MarshalJSON() ([]byte, error) {
	tcp := map[string]any{
		"tlsrec":      desyncPositions(d.tcp.TLSRec),
		"split":       desyncPositions(d.tcp.Split),
		"split-delay": d.tcp.SplitDelay.Milliseconds(),
		"fake":        nil,
	}
	if fake := d.tcp.Fake; fake != nil {
		timeout := fake.Timeout
		if timeout == 0 {
			timeout = 3 * time.Second
		}
		tcp["fake"] = map[string]any{"ttl": fake.TTL, "prefix": fake.Prefix, "timeout": timeout.Milliseconds()}
	}
	var udp any
	if d.udp != nil {
		udp = map[string]any{
			"ttl":      d.udp.TTL,
			"repeats":  d.udp.Repeats,
			"packets":  d.udp.Packets,
			"counters": d.udp.Counters.Snapshot(),
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

func (o DesyncOption) tcpOptions() (opts desync.Options, err error) {
	if opts.TLSRec, err = parseDesyncPositions(o.TLSRec); err != nil {
		return opts, fmt.Errorf("tlsrec: %w", err)
	}
	if opts.Split, err = parseDesyncPositions(o.Split); err != nil {
		return opts, fmt.Errorf("split: %w", err)
	}
	if opts.SplitDelay, err = desyncMilliseconds("split-delay", o.SplitDelay, desyncMaxSplitDelay); err != nil {
		return opts, err
	}
	if opts.SplitDelay > 0 && len(opts.Split) == 0 {
		return opts, errors.New("split-delay needs split positions")
	}
	if o.Fake != nil {
		if !desync.SupportsFake() {
			return opts, fmt.Errorf("fake is supported on Windows only, not on %s: %w", runtime.GOOS, desync.ErrFakeUnsupported)
		}
		timeout, err := desyncMilliseconds("fake timeout", o.Fake.Timeout, desyncMaxFakeTimeout)
		if err != nil {
			return opts, err
		}
		opts.Fake = &desync.FakeOptions{TTL: o.Fake.TTL, Prefix: o.Fake.Prefix, Timeout: timeout}
	}
	return opts, opts.Validate()
}

func (o DesyncOption) udpOptions() (*desync.UDPOptions, error) {
	if o.UDP == nil {
		return nil, nil
	}
	if !desync.SupportsUDPFake() {
		return nil, fmt.Errorf("udp is supported on Windows only, not on %s: %w", runtime.GOOS, desync.ErrUDPFakeUnsupported)
	}
	opts := desync.UDPOptions{TTL: o.UDP.TTL, Repeats: o.UDP.Repeats, Packets: o.UDP.Packets}
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	// The library's defaults, filled in here so that the API shows them.
	if opts.Repeats == 0 {
		opts.Repeats = 6
	}
	if opts.Packets == 0 {
		opts.Packets = 3
	}
	opts.Counters = &desync.UDPCounters{} // shared by all sockets of the outbound
	return &opts, nil
}

// NewDesync validates the options; anything the platform or the library
// cannot do is a configuration error, never a silent plain DIRECT.
func NewDesync(option DesyncOption) (*Desync, error) {
	d, err := newDesync(option)
	if err != nil {
		return nil, fmt.Errorf("desync %q: %w", option.Name, err)
	}
	return d, nil
}

func newDesync(option DesyncOption) (*Desync, error) {
	// TFO sends the first write with the SYN, before the transformer could
	// cut it; MPTCP spreads it over subflows that no longer match the cuts,
	// and the Windows fake needs a plain TCP socket.
	if option.TFO {
		return nil, errors.New("tfo is not supported: the ClientHello would leave with the SYN")
	}
	if option.MPTCP {
		return nil, errors.New("mptcp is not supported")
	}
	if option.DialerProxy != "" {
		return nil, errors.New("dialer-proxy is not supported: desync dials directly")
	}
	tcp, err := option.tcpOptions()
	if err != nil {
		return nil, err
	}
	udp, err := option.udpOptions()
	if err != nil {
		return nil, err
	}
	if !tcp.Enabled() && udp == nil {
		return nil, errors.New("set at least one of tlsrec, split, fake or udp")
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
// not just the ClientHello: the Windows fake may still own the socket after
// the hello was accepted, and an extra copy of the upload is cheap next to a
// bypass. Reads are untouched by desync, so the reader is replaceable and the
// relay reads the socket directly (splice of the download on Linux).
type desyncConn struct {
	net.Conn          // *desync.Conn
	socket   net.Conn // the dialed socket, for reading only
}

func newDesyncConn(socket, transformed net.Conn, a C.ProxyAdapter) C.Conn {
	dc := &desyncConn{Conn: transformed, socket: socket}
	// Not NewConn: the deadline wrapper it adds for outbound conns is not
	// needed (deadlines go to the socket) and would hide the raw reader.
	cc := &conn{ExtendedConn: N.NewExtendedConn(dc), adapterAddr: a.Addr()}
	cc.AppendToChains(a)
	return cc
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
