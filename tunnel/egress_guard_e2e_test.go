package tunnel_test

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/egress"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	RC "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// guardLog collects the log lines of the egress guard's refusals.
type guardLog struct {
	mu    sync.Mutex
	lines []string
	added chan struct{}
}

func watchGuardLog(t *testing.T) *guardLog {
	t.Helper()
	g := &guardLog{added: make(chan struct{}, 1)}
	sub := log.Subscribe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for event := range sub {
			// the later drops of a UDP session are logged at debug
			if event.LogLevel != log.WARNING || !strings.Contains(event.Payload, "egress guard blocked") {
				continue
			}
			g.mu.Lock()
			g.lines = append(g.lines, event.Payload)
			g.mu.Unlock()
			select {
			case g.added <- struct{}{}:
			default:
			}
		}
	}()
	t.Cleanup(func() {
		log.UnSubscribe(sub)
		<-done
	})
	return g
}

// take returns and forgets the refusals logged so far. The log is delivered
// asynchronously: with want it waits a moment for the first one, without it
// gives a late one a moment to show up.
func (g *guardLog) take(want bool) []string {
	if want {
		deadline := time.After(2 * time.Second)
		for {
			g.mu.Lock()
			n := len(g.lines)
			g.mu.Unlock()
			if n > 0 {
				break
			}
			select {
			case <-g.added:
			case <-deadline:
				return nil
			}
		}
	} else {
		time.Sleep(100 * time.Millisecond)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	lines := g.lines
	g.lines = nil
	return lines
}

// blocked asserts that the connection did not get through because the guard
// refused it in DIRECT (after rule, when not empty), not for another reason.
func blocked(t *testing.T, logs *guardLog, reached bool, rule, msg string) {
	t.Helper()
	assert.False(t, reached, msg)
	lines := logs.take(true)
	if assert.Len(t, lines, 1, "%s: the refusal of the guard must be logged once", msg) {
		assert.Contains(t, lines[0], "dial DIRECT", msg)
		assert.Contains(t, lines[0], "server-in (user alice)", msg)
		if rule != "" {
			assert.Contains(t, lines[0], rule, msg)
		}
	}
}

// passed asserts that the connection got through and the guard logged nothing.
func passed(t *testing.T, logs *guardLog, reached bool, msg string) {
	t.Helper()
	assert.True(t, reached, msg)
	assert.Empty(t, logs.take(false), msg)
}

// reaches hands one TCP connection for host:port (or the IP literal when
// host is empty) from an inbound of typ to the tunnel and reports whether
// the listener received it.
func reaches(t *testing.T, typ C.Type, guard C.EgressGuard, host string) bool {
	t.Helper()
	ln := listen(t)
	port := ln.Addr().(*net.TCPAddr).Port

	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- struct{}{}
		_ = c.Close()
	}()

	client, server := net.Pipe()
	defer client.Close()
	metadata := &C.Metadata{
		NetWork:     C.TCP,
		Type:        typ,
		InName:      "server-in",
		InUser:      "alice",
		EgressGuard: guard,
		SrcIP:       netip.MustParseAddr("198.51.100.7"),
		SrcPort:     40000,
		Host:        host,
		DstPort:     uint16(port),
	}
	if host == "" {
		metadata.DstIP = netip.MustParseAddr("127.0.0.1")
	}
	done := make(chan struct{})
	go func() {
		tunnel.Tunnel.HandleTCPConn(server, metadata)
		close(done)
	}()

	var ok bool
	select {
	case <-accepted:
		ok = true
	case <-done: // refused without a dial
	case <-time.After(3 * time.Second):
	}
	_ = client.Close()
	_ = ln.Close()
	<-done
	return ok
}

func withEgress(t *testing.T, o egress.Options) {
	t.Helper()
	old := egress.CurrentOptions()
	egress.SetOptions(o)
	t.Cleanup(func() { egress.SetOptions(old) })
}

// An explicit rule that sends the loopback to DIRECT does not open it to the
// users of a server inbound, for an IP literal or a domain that resolves to
// it: the rule matches and DIRECT's guard refuses the dial. The local client
// inbounds are routed as before.
func TestEgressGuardRulesCannotBypass(t *testing.T) {
	withEgress(t, egress.Options{Enable: true})
	loopback := &sequenceResolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	direct, err := RC.NewIPCIDR("127.0.0.0/8", "DIRECT")
	require.NoError(t, err)
	setupTunnel(t, []C.Rule{direct, RC.NewMatch("DIRECT")}, loopback, loopback)
	logs := watchGuardLog(t)

	rule := "(match " + direct.RuleType().String() + "/127.0.0.0/8)"
	for _, typ := range []C.Type{C.VLESS, C.TROJAN, C.SHADOWSOCKS, C.ANYTLS} {
		blocked(t, logs, reaches(t, typ, C.EgressGuardDefault, ""), rule, typ.String()+": IP literal")
		blocked(t, logs, reaches(t, typ, C.EgressGuardDefault, "rebind.example"), rule, typ.String()+": resolved domain")
	}
	passed(t, logs, reaches(t, C.SOCKS5, C.EgressGuardDefault, ""), "client inbound, IP literal")
	passed(t, logs, reaches(t, C.SOCKS5, C.EgressGuardDefault, "rebind.example"), "client inbound, domain")
}

// The ways to open it on purpose: the listener's egress-guard: false and the
// allow-list. And egress-guard: true closes a client listener.
func TestEgressGuardOverrides(t *testing.T) {
	withEgress(t, egress.Options{Enable: true})
	loopback := &sequenceResolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	setupTunnel(t, []C.Rule{RC.NewMatch("DIRECT")}, loopback, loopback)
	logs := watchGuardLog(t)

	passed(t, logs, reaches(t, C.VLESS, C.EgressGuardOff, "rebind.example"), "egress-guard: false")
	blocked(t, logs, reaches(t, C.SOCKS5, C.EgressGuardOn, "rebind.example"), "", "egress-guard: true")

	egress.SetOptions(egress.Options{Enable: true, AllowIPs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	passed(t, logs, reaches(t, C.VLESS, C.EgressGuardDefault, "rebind.example"), "allow-ips")

	egress.SetOptions(egress.Options{Enable: false})
	passed(t, logs, reaches(t, C.VLESS, C.EgressGuardDefault, ""), "enable: false")
	blocked(t, logs, reaches(t, C.SOCKS5, C.EgressGuardOn, ""), "", "enable: false, egress-guard: true")
}

// udpPacket is a datagram from the user of a server inbound.
type udpPacket struct {
	data []byte
	src  *net.UDPAddr
}

func (p *udpPacket) Data() []byte                                { return p.data }
func (p *udpPacket) WriteBack(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (p *udpPacket) Drop()                                       {}
func (p *udpPacket) LocalAddr() net.Addr                         { return p.src }

// A UDP session through the whole tunnel whose first datagram goes to a
// blocked address, and the next ones alternate between a blocked and an
// allowed one. The blocked datagrams are dropped and logged once, the
// session is not torn down (and dialed again) for them, and the allowed ones
// get through.
func TestEgressGuardUDPSession(t *testing.T) {
	withEgress(t, egress.Options{Enable: true, AllowIPs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	loopback := &sequenceResolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	setupTunnel(t, []C.Rule{RC.NewMatch("DIRECT")}, loopback, loopback)

	allowed, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer allowed.Close()
	blockedUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.2: %v", err)
	}
	defer blockedUDP.Close()
	logs := watchGuardLog(t)

	// a source port of its own: a session of an earlier run (-count) is still
	// in the NAT table, and its warning was already logged
	src := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: allowed.LocalAddr().(*net.UDPAddr).Port}
	send := func(payload string, dst *net.UDPAddr) {
		metadata := &C.Metadata{
			NetWork: C.UDP,
			Type:    C.VLESS,
			InName:  "server-in",
			InUser:  "alice",
			SrcIP:   netip.MustParseAddr("198.51.100.7"),
			SrcPort: uint16(src.Port),
			DstIP:   dst.AddrPort().Addr(),
			DstPort: uint16(dst.Port),
		}
		tunnel.Tunnel.HandleUDPPacket(&udpPacket{data: []byte(payload), src: src}, metadata)
	}
	allowedAddr, blockedAddr := allowed.LocalAddr().(*net.UDPAddr), blockedUDP.LocalAddr().(*net.UDPAddr)

	send("blocked-1", blockedAddr)
	send("allowed-1", allowedAddr)
	send("blocked-2", blockedAddr)
	send("allowed-2", allowedAddr)
	send("blocked-3", blockedAddr)

	buf := make([]byte, 64)
	for _, want := range []string{"allowed-1", "allowed-2"} {
		_ = allowed.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := allowed.ReadFromUDP(buf)
		require.NoError(t, err, "waiting for %s", want)
		assert.Equal(t, want, string(buf[:n]))
	}
	_ = blockedUDP.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err = blockedUDP.ReadFromUDP(buf)
	assert.Error(t, err, "nothing may reach the blocked address")

	lines := logs.take(true)
	time.Sleep(100 * time.Millisecond) // a second warning would be late too
	lines = append(lines, logs.take(false)...)
	if assert.Len(t, lines, 1, "one session, one warning: %v", lines) {
		assert.Contains(t, lines[0], "127.0.0.2")
		assert.Contains(t, lines[0], "server-in (user alice)")
	}
}
