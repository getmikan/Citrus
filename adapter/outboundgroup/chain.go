package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/eventbus"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// Chain is a cascade of hops: the configuration wires every hop after the
// first one to the hop before it (dialer-proxy), so dialing the last hop
// goes through all of them. A hop can be a proxy or a group.
//
// Its health check tests the whole chain (the last hop), and when the chain
// fails it tests the hops from the first one to find the hop that breaks it:
// testing hop k goes through hops 1..k.
type Chain struct {
	*GroupBase
	hops           []C.Proxy
	disableUDP     bool
	testUrl        string
	expectedStatus string

	mu    sync.RWMutex
	state chainState
}

// chainState is the result of the last health check of a chain.
type chainState struct {
	checked time.Time
	alive   bool
	// failed is the index of the first hop that failed, -1 when alive
	failed int
	err    string
}

// ChainHop is the state of a hop of a chain, as /proxies shows it.
type ChainHop struct {
	Name     string `json:"name"`
	Position int    `json:"position"`
	// Alive is nil when the last health check did not tell the state of the
	// hop: it was not run yet, or an earlier hop failed.
	Alive *bool `json:"alive"`
}

// Hops returns the hops of the chain, from the first one.
func (c *Chain) Hops() []C.Proxy {
	return c.hops
}

func (c *Chain) last() C.Proxy {
	return c.hops[len(c.hops)-1]
}

func (c *Chain) Now() string {
	return c.last().Name()
}

// DialContext implements C.ProxyAdapter
func (c *Chain) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c.Touch()
	last := c.last()
	conn, err := last.DialContext(ctx, metadata)
	if err == nil {
		conn.AppendToChains(c)
	} else {
		c.onDialFailed(last.Type(), err, c.GroupBase.healthCheck)
	}
	return conn, err
}

// ListenPacketContext implements C.ProxyAdapter
func (c *Chain) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	c.Touch()
	pc, err := c.last().ListenPacketContext(ctx, metadata)
	if err == nil {
		pc.AppendToChains(c)
	}
	return pc, err
}

// SupportUDP implements C.ProxyAdapter
func (c *Chain) SupportUDP() bool {
	if c.disableUDP {
		return false
	}
	return c.last().SupportUDP()
}

// IsL3Protocol implements C.ProxyAdapter
func (c *Chain) IsL3Protocol(metadata *C.Metadata) bool {
	return c.last().IsL3Protocol(metadata)
}

// Unwrap implements C.ProxyAdapter
func (c *Chain) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	if touch {
		c.Touch()
	}
	return c.last()
}

func (c *Chain) Providers() []P.ProxyProvider {
	return c.providers
}

func (c *Chain) Proxies() []C.Proxy {
	return c.hops
}

// URLTest tests the chain as its health check does, with url, and returns
// the delays of what was tested: the chain (under the name of the last hop)
// and, when it failed, the hops from the first one up to the failed hop. The
// result is kept as the state of the chain when url is its test URL.
func (c *Chain) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (map[string]uint16, error) {
	st, delays := c.check(ctx, url, expectedStatus, 0, url == c.testUrl)
	if !st.alive {
		return delays, errors.New(st.err)
	}
	return delays, nil
}

// healthCheck is the Checker of the health check of the chain.
func (c *Chain) healthCheck(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16], timeout time.Duration) {
	c.check(ctx, url, expectedStatus, timeout, true)
}

func (c *Chain) check(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16], timeout time.Duration, record bool) (chainState, map[string]uint16) {
	delays := map[string]uint16{}
	test := func(p C.Proxy) bool {
		tctx := ctx
		if timeout > 0 {
			var cancel context.CancelFunc
			tctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		delay, err := p.URLTest(tctx, url, expectedStatus)
		if err != nil || !p.AliveForTestUrl(url) {
			return false
		}
		delays[p.Name()] = delay
		return true
	}

	st := chainState{checked: time.Now(), failed: -1}
	if test(c.last()) {
		st.alive = true
	} else {
		// the chain is down: find the first hop that does not get through
		st.failed = len(c.hops) - 1
		for i, hop := range c.hops[:len(c.hops)-1] {
			if ctx.Err() != nil {
				break
			}
			if !test(hop) {
				st.failed = i
				break
			}
		}
		if ctx.Err() != nil {
			// the time of the test ran out (or the configuration was replaced):
			// a hop tested now would fail for that, not for itself
			return chainState{failed: -1, err: fmt.Sprintf("chain %s failed, the test ran out of time before finding the hop", c.Name())}, delays
		}
		hop := c.hops[st.failed]
		if st.failed == 0 {
			st.err = fmt.Sprintf("chain %s: hop 1 [%s] failed", c.Name(), hop.Name())
		} else {
			st.err = fmt.Sprintf("chain %s: hop %d [%s] failed, the hops before it are alive", c.Name(), st.failed+1, hop.Name())
		}
	}
	if !record {
		return st, delays
	}

	c.mu.Lock()
	prev := c.state
	c.state = st
	c.mu.Unlock()

	if prev.checked.IsZero() && st.alive {
		return st, delays
	}
	if prev.checked.IsZero() || prev.alive != st.alive || prev.failed != st.failed {
		if eventbus.Enabled(eventbus.TypeChainHealth) {
			d := eventbus.ChainHealth{Chain: c.Name(), Alive: st.alive, Error: st.err}
			if !st.alive {
				d.FailedHop = c.hops[st.failed].Name()
				d.Position = st.failed + 1
			}
			eventbus.Publish(eventbus.TypeChainHealth, d)
		}
	}
	return st, delays
}

// ChainStatus is the state of a chain after its last health check.
type ChainStatus struct {
	// Checked is false before the first health check; then Alive and the
	// hops tell nothing.
	Checked bool
	Alive   bool
	// FailedHop is the index of the first hop that failed, -1 when none.
	FailedHop int
	Error     string
	Hops      []ChainHop
}

// Status returns the state of the chain after its last health check.
func (c *Chain) Status() ChainStatus {
	c.mu.RLock()
	st := c.state
	c.mu.RUnlock()

	out := ChainStatus{Checked: !st.checked.IsZero(), Alive: st.alive, FailedHop: st.failed, Error: st.err}
	if !out.Checked {
		out.FailedHop = -1
	}
	yes, no := true, false
	for i, hop := range c.hops {
		h := ChainHop{Name: hop.Name(), Position: i + 1}
		if out.Checked {
			switch {
			case st.alive || i < st.failed:
				h.Alive = &yes
			case i == st.failed:
				h.Alive = &no
			}
		}
		out.Hops = append(out.Hops, h)
	}
	return out
}

// MarshalJSON implements C.ProxyAdapter
func (c *Chain) MarshalJSON() ([]byte, error) {
	all := make([]string, 0, len(c.hops))
	for _, hop := range c.hops {
		all = append(all, hop.Name())
	}
	st := c.Status()
	m := map[string]any{
		"type":           c.Type().String(),
		"now":            c.Now(),
		"all":            all,
		"testUrl":        c.testUrl,
		"expectedStatus": c.expectedStatus,
		"hidden":         c.Hidden(),
		"icon":           c.Icon(),
		"hops":           st.Hops,
	}
	if st.Checked {
		m["chainAlive"] = st.Alive
		if !st.Alive {
			m["failedHop"] = c.hops[st.FailedHop].Name()
			m["failedHopPosition"] = st.FailedHop + 1
			m["chainError"] = st.Error
		}
	}
	return json.Marshal(m)
}

func newChain(option *GroupCommonOption, hops []C.Proxy, expectedStatus utils.IntRanges[uint16]) (*Chain, error) {
	if len(hops) < 2 {
		return nil, fmt.Errorf("%s: a chain needs at least two hops", option.Name)
	}
	if option.URL == "" {
		option.URL = C.DefaultTestURL
	}
	if option.Interval == 0 {
		option.Interval = 300
	}

	hc := provider.NewHealthCheck(hops, option.URL, uint(option.TestTimeout), uint(option.Interval), option.Lazy, expectedStatus)
	pd, err := provider.NewCompatibleProvider(option.Name, hops, hc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", option.Name, err)
	}

	c := &Chain{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:        option.Name,
			Type:        C.ChainGroup,
			Hidden:      option.Hidden,
			Icon:        option.Icon,
			TestTimeout: option.TestTimeout,
			Providers:   []P.ProxyProvider{pd},
		}),
		hops:           hops,
		disableUDP:     option.DisableUDP,
		testUrl:        option.URL,
		expectedStatus: option.ExpectedStatus,
		state:          chainState{failed: -1},
	}
	hc.SetChecker(c.healthCheck)
	return c, nil
}
