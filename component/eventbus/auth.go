package eventbus

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/authevent"
)

// Auth is the data of an auth event.
//
// A failure comes from the inbound protocols (component/authevent): the
// client is not known, so it carries the protocol and the listener address.
// A success is a user seen from a new client address (an address that is not
// online for the user yet); it carries the inbound and the user, and is only
// reported while per-user statistics or limits are on.
//
// The events are aggregated so that a scanner cannot flood the stream: the
// first attempt of a client (by address, not port) with the same outcome is
// reported at once with Count 1; the repetitions within AuthWindow are
// counted and reported in one event with Repeated set when the window ends.
// At most AuthMaxKeys clients are tracked per window; the attempts of the
// others are summed into one event per result with Overflow set.
type Auth struct {
	// Result is "success" or "failure".
	Result   string `json:"result"`
	Inbound  string `json:"inbound,omitempty"`
	User     string `json:"user,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Local    string `json:"local,omitempty"`
	// Remote is the client IP address, without the port.
	Remote string `json:"remote,omitempty"`
	// Reason is the reason of a failure, see the authevent Reason constants.
	Reason   string `json:"reason,omitempty"`
	Count    int64  `json:"count"`
	Repeated bool   `json:"repeated,omitempty"`
	Overflow bool   `json:"overflow,omitempty"`
}

// Results of an auth event.
const (
	AuthSuccess = "success"
	AuthFailure = "failure"
)

// Aggregation of the auth events, see Auth.
var (
	AuthWindow  = 5 * time.Second
	AuthMaxKeys = 256
)

type authKey struct {
	result, inbound, user, protocol, local, remote, reason string
}

type authAggregator struct {
	mu       sync.Mutex
	pending  map[authKey]int64 // repetitions since the first report
	overflow map[string]int64  // attempts of untracked clients, by result
	timer    *time.Timer
	bus      *Bus
}

var defaultAuth = &authAggregator{bus: Default}

func init() {
	authevent.SetTap(func() bool { return Enabled(TypeAuth) }, func(e authevent.Event) {
		defaultAuth.add(authKey{result: AuthFailure, protocol: e.Protocol, local: e.Local, remote: hostOnly(e.Remote), reason: e.Reason})
	})
}

// PublishAuthSuccess reports that user of inbound authenticated from a new
// address ip.
func PublishAuthSuccess(inbound, user string, ip netip.Addr) {
	if !Enabled(TypeAuth) {
		return
	}
	remote := ""
	if ip.IsValid() {
		remote = ip.String()
	}
	defaultAuth.add(authKey{result: AuthSuccess, inbound: inbound, user: user, remote: remote})
}

func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func (a *authAggregator) add(k authKey) {
	a.mu.Lock()
	if n, ok := a.pending[k]; ok {
		a.pending[k] = n + 1
		a.mu.Unlock()
		return
	}
	if a.pending == nil {
		a.pending = make(map[authKey]int64)
	}
	if len(a.pending) >= AuthMaxKeys {
		if a.overflow == nil {
			a.overflow = make(map[string]int64)
		}
		a.overflow[k.result]++
		a.mu.Unlock()
		return
	}
	a.pending[k] = 0
	if a.timer == nil {
		a.timer = time.AfterFunc(AuthWindow, a.flush)
	}
	a.mu.Unlock()
	a.bus.Publish(TypeAuth, k.event(1))
}

// flush ends the window: the repetitions are reported and the clients
// forgotten.
func (a *authAggregator) flush() {
	a.mu.Lock()
	pending, overflow := a.pending, a.overflow
	a.pending, a.overflow, a.timer = nil, nil, nil
	a.mu.Unlock()
	for k, n := range pending {
		if n > 0 {
			e := k.event(n)
			e.Repeated = true
			a.bus.Publish(TypeAuth, e)
		}
	}
	for result, n := range overflow {
		a.bus.Publish(TypeAuth, Auth{Result: result, Count: n, Overflow: true})
	}
}

func (k authKey) event(n int64) Auth {
	return Auth{Result: k.result, Inbound: k.inbound, User: k.user, Protocol: k.protocol, Local: k.local, Remote: k.remote, Reason: k.reason, Count: n}
}
