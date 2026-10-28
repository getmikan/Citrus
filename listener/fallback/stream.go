package fallback

import (
	"bytes"
	gotls "crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/proxyproto"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/tls"
	utls "github.com/metacubex/utls"
)

// Target is one of the fallbacks of a VLESS or Trojan inbound on its plain
// TCP transport (Xray-core "fallbacks"): where a connection that is not the
// inbound's own goes, after its TLS layer, with the bytes read from it.
type Target struct {
	// Name matches the TLS SNI: a name, "*.example.com" for any name under
	// example.com, or "" for any (and for no TLS).
	Name string `json:"name,omitempty"`
	// ALPN matches the negotiated ALPN ("h2", "http/1.1"), "" for any.
	ALPN string `json:"alpn,omitempty"`
	// Path matches the path of an HTTP/1.x request line at the start of the
	// stream ("/x" of "GET /x?y HTTP/1.1"), "" for any.
	Path string `json:"path,omitempty"`
	// Dest is a port on 127.0.0.1 ("8080"), a host:port, or a unix socket
	// ("/run/nginx.sock", "@abstract" on Linux, "unix:C:\x.sock").
	Dest string `json:"dest"`
	// Xver is the PROXY protocol header version sent first to Dest, 1 or 2;
	// 0 sends none.
	Xver int `json:"xver,omitempty"`
}

// MaxPeek is the most a stream is read before its fallback is chosen; a path
// that does not end in it matches no Path.
const MaxPeek = 256

// dialTimeout bounds the connect to a Dest, which is expected to be local.
const dialTimeout = 5 * time.Second

type target struct {
	Target
	network, address string
}

// Streams is the fallbacks of an inbound: it reads the start of a connection
// for the protocol to tell its own from others (Sniff), and relays the others
// to the Target that matches them best, under the limits of Limiter.
type Streams struct {
	targets  []target
	needPath bool
	limiter  Limiter
	tag      string
}

// NewStreams validates targets; tag names the inbound type in the logs.
func NewStreams(tag string, targets []Target) (*Streams, error) {
	s := &Streams{tag: tag}
	type key struct{ name, alpn, path string }
	seen := make(map[key]bool)
	for i, t := range targets {
		t.Name = strings.ToLower(t.Name)
		if strings.Contains(strings.TrimPrefix(t.Name, "*."), "*") {
			return nil, fmt.Errorf("fallbacks[%d]: name %q: only a leading \"*.\" is a wildcard", i, t.Name)
		}
		if t.Path != "" && !strings.HasPrefix(t.Path, "/") {
			return nil, fmt.Errorf("fallbacks[%d]: path %q must start with /", i, t.Path)
		}
		if len(t.Path) >= MaxPeek {
			return nil, fmt.Errorf("fallbacks[%d]: path longer than %d bytes never matches", i, MaxPeek-1)
		}
		if t.Xver < 0 || t.Xver > 2 {
			return nil, fmt.Errorf("fallbacks[%d]: xver %d, want 0, 1 or 2", i, t.Xver)
		}
		k := key{t.Name, t.ALPN, t.Path}
		if seen[k] {
			return nil, fmt.Errorf("fallbacks[%d]: another fallback has the same name %q, alpn %q and path %q", i, t.Name, t.ALPN, t.Path)
		}
		seen[k] = true
		network, address, err := parseDest(t.Dest)
		if err != nil {
			return nil, fmt.Errorf("fallbacks[%d]: %w", i, err)
		}
		s.targets = append(s.targets, target{Target: t, network: network, address: address})
		s.needPath = s.needPath || t.Path != ""
	}
	if len(s.targets) == 0 {
		return nil, nil
	}
	return s, nil
}

// NextProtos is the ALPN list the TLS layer of an inbound with targets offers:
// nil when no target matches by ALPN (no ALPN is negotiated, as without
// fallbacks), else the ALPNs of the targets in their order, and http/1.1. A
// client that offers ALPNs but none of these fails the handshake (Go's TLS
// server answers no_application_protocol); http/1.1, always listed, is enough.
func NextProtos(targets []Target) []string {
	var protos []string
	for _, t := range targets {
		if t.ALPN != "" && !slices.Contains(protos, t.ALPN) {
			protos = append(protos, t.ALPN)
		}
	}
	if len(protos) > 0 && !slices.Contains(protos, "http/1.1") {
		protos = append(protos, "http/1.1")
	}
	return protos
}

func parseDest(dest string) (network, address string, err error) {
	switch {
	case dest == "":
		return "", "", errors.New("dest is required")
	case strings.HasPrefix(dest, "unix:"):
		return "unix", strings.TrimPrefix(dest, "unix:"), nil
	case strings.HasPrefix(dest, "/"), strings.HasPrefix(dest, "@"):
		return "unix", dest, nil
	}
	if port, err := strconv.ParseUint(dest, 10, 16); err == nil && port > 0 {
		return "tcp", net.JoinHostPort("127.0.0.1", dest), nil
	}
	host, port, err := net.SplitHostPort(dest)
	if p, perr := strconv.ParseUint(port, 10, 16); err != nil || host == "" || perr != nil || p == 0 {
		return "", "", fmt.Errorf("dest %q: want a port, host:port or a unix socket path", dest)
	}
	return "tcp", dest, nil
}

// Close closes the open relays and refuses new ones.
func (s *Streams) Close() { s.limiter.Close() }

// Verdict is what a protocol makes of the start of a stream.
type Verdict int

const (
	// More: the bytes so far could be the protocol's, read more.
	More Verdict = iota
	// Own: the stream is the protocol's.
	Own
	// Other: the stream is not the protocol's, it goes to a fallback.
	Other
)

// Sniff reads the start of conn, at most limit (<= MaxPeek) bytes and no more
// than classify asks for, until classify, given all of them, says whose it
// is. For the protocol's own it returns conn with the bytes put back, true.
// Otherwise it serves the fallback (or closes conn) and returns false; it
// blocks until the relay ends.
//
// conn must have the handshake deadline set: it bounds the reads here, and a
// stream that stops while it could still be the protocol's is closed at it,
// as without fallbacks. On TLS, the first read finishes the handshake. Unlike
// Xray-core, which decides on the first read alone, the header may come in
// pieces.
func (s *Streams) Sniff(conn net.Conn, limit int, classify func([]byte) Verdict) (net.Conn, bool) {
	buf := make([]byte, MaxPeek)
	n := 0
	verdict := More
	for verdict == More && n < limit {
		m, err := conn.Read(buf[n:limit])
		n += m
		if m > 0 {
			verdict = classify(buf[:n])
		}
		if err != nil && verdict == More {
			_ = conn.Close()
			return nil, false
		}
	}
	if verdict == More {
		// classify asked for more than limit
		verdict = classify(buf[:n])
		if verdict == More {
			verdict = Other
		}
	}
	if verdict == Own {
		return N.NewCachedConn(conn, buf[:n]), true
	}
	if s.needPath {
		n = readRequestLine(conn, buf, n)
	}
	s.serve(conn, buf[:n])
	return nil, false
}

// readRequestLine reads on until buf[:n] holds the path of an HTTP/1.x
// request line, is no such line, or fills buf. A read error ends it with what
// was read: a timeout (the handshake deadline) or EOF still forwards the
// bytes, whose path is unknown.
func readRequestLine(conn net.Conn, buf []byte, n int) int {
	for n < len(buf) {
		if _, done := requestPath(buf[:n]); done {
			break
		}
		m, err := conn.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
	}
	return n
}

// requestPath returns the path of the HTTP/1.x request line at the start of
// b, "/x" of "GET /x?y HTTP/1.1"; done is false when b is a prefix of one that
// has not reached the end of the path yet. h2 ("PRI * HTTP/2.0") and anything
// else have no path.
func requestPath(b []byte) (path string, done bool) {
	const maxMethod = 16
	sp := bytes.IndexByte(b, ' ')
	method := b
	if sp >= 0 {
		method = b[:sp]
	}
	if len(method) > maxMethod || sp == 0 {
		return "", true
	}
	for _, c := range method {
		if c < 'A' || c > 'Z' {
			return "", true
		}
	}
	if sp < 0 {
		return "", false
	}
	rest := b[sp+1:]
	if len(rest) == 0 {
		return "", false
	}
	if rest[0] != '/' {
		return "", true
	}
	if end := bytes.IndexAny(rest, " ?#\r\n"); end >= 0 {
		if rest[end] == '\r' || rest[end] == '\n' {
			return "", true // HTTP/0.9 or garbage: no version, no match
		}
		return string(rest[:end]), true
	}
	return "", false
}

// tlsInfo returns the SNI and the negotiated ALPN of conn, empty when it is
// not TLS (or not a TLS that tells).
func tlsInfo(conn net.Conn) (sni, alpn string) {
	var upstream any = conn
	for range 8 {
		switch c := upstream.(type) {
		case interface{ ConnectionState() tls.ConnectionState }:
			state := c.ConnectionState()
			return state.ServerName, state.NegotiatedProtocol
		case interface{ ConnectionState() utls.ConnectionState }:
			state := c.ConnectionState()
			return state.ServerName, state.NegotiatedProtocol
		case interface{ ConnectionState() gotls.ConnectionState }:
			state := c.ConnectionState()
			return state.ServerName, state.NegotiatedProtocol
		case N.WithUpstream:
			upstream = c.Upstream()
		default:
			return "", ""
		}
	}
	return "", ""
}

// match returns the most specific target that matches: by name first (exact,
// then the longest wildcard, then any), then ALPN, then path; nil for none.
func (s *Streams) match(sni, alpn, path string) *target {
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	var best *target
	var bestRank [3]int
	for i := range s.targets {
		t := &s.targets[i]
		var rank [3]int
		switch {
		case t.Name == "":
		case t.Name == sni:
			rank[0] = 1 << 16
		case strings.HasPrefix(t.Name, "*.") && strings.HasSuffix(sni, t.Name[1:]):
			rank[0] = len(t.Name)
		default:
			continue
		}
		if t.ALPN != "" {
			if t.ALPN != alpn {
				continue
			}
			rank[1] = 1
		}
		if t.Path != "" {
			if t.Path != path {
				continue
			}
			rank[2] = 1
		}
		if best == nil || rank[0] > bestRank[0] ||
			rank[0] == bestRank[0] && (rank[1] > bestRank[1] || rank[1] == bestRank[1] && rank[2] > bestRank[2]) {
			best, bestRank = t, rank
		}
	}
	return best
}

// serve relays conn, of which prefix is read, to its target; it closes conn.
func (s *Streams) serve(conn net.Conn, prefix []byte) {
	defer conn.Close()
	sni, alpn := tlsInfo(conn)
	path, _ := requestPath(prefix)
	t := s.match(sni, alpn, path)
	if t == nil {
		log.Debugln("[%s] %s: no fallback for sni %q alpn %q path %q", s.tag, conn.RemoteAddr(), sni, alpn, path)
		return
	}
	r, ok := s.limiter.Acquire(conn)
	if !ok {
		return
	}
	defer s.limiter.Release(r)
	dialer := net.Dialer{Timeout: dialTimeout}
	backend, err := dialer.Dial(t.network, t.address)
	if err != nil {
		log.Warnln("[%s] fallback %s: %v", s.tag, t.Dest, err)
		return
	}
	defer backend.Close()
	if !s.limiter.Attach(r, backend) {
		return
	}
	head := make([]byte, 0, 64+len(prefix))
	if t.Xver != 0 {
		head, _ = proxyproto.Header{
			Version:     t.Xver,
			Source:      addrPort(conn.RemoteAddr()),
			Destination: addrPort(conn.LocalAddr()),
		}.Append(head) // the version is validated
	}
	head = append(head, prefix...)
	_ = backend.SetWriteDeadline(time.Now().Add(dialTimeout))
	if _, err := backend.Write(head); err != nil {
		return
	}
	_ = backend.SetWriteDeadline(time.Time{})
	// the stream is classified: lift the handshake deadline
	_ = conn.SetDeadline(time.Time{})
	idle := NewIdleGuard(IdleTimeout, conn, backend)
	defer idle.Stop()
	N.Relay(idle.Wrap(conn), idle.Wrap(backend))
}

// addrPort is the IP address and port of addr, invalid when it has none.
func addrPort(addr net.Addr) netip.AddrPort {
	switch a := addr.(type) {
	case nil:
		return netip.AddrPort{}
	case *net.TCPAddr:
		return a.AddrPort()
	}
	ap, _ := netip.ParseAddrPort(addr.String())
	return ap
}
