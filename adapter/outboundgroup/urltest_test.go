package outboundgroup

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/singledo"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// urlTestProxy is a minimal C.Proxy for url-test selection tests. A delay of
// 0xffff mirrors adapter.Proxy for an alive proxy that has not been measured
// yet (e.g. a fresh instance right after a provider update).
type urlTestProxy struct {
	C.Proxy
	name  string
	alive bool
	delay uint16
}

func (p *urlTestProxy) Name() string                { return p.name }
func (p *urlTestProxy) AliveForTestUrl(string) bool { return p.alive }
func (p *urlTestProxy) LastDelayForTestUrl(string) uint16 {
	if !p.alive {
		return 0xffff
	}
	return p.delay
}

type urlTestProvider struct {
	P.ProxyProvider
	proxies []C.Proxy
	version uint32
}

func (p *urlTestProvider) Proxies() []C.Proxy { return p.proxies }
func (p *urlTestProvider) Version() uint32    { return p.version }
func (p *urlTestProvider) Touch()             {}

// update simulates a provider refresh: new instances, bumped version.
func (p *urlTestProvider) update(proxies ...C.Proxy) {
	p.proxies = proxies
	p.version++
}

func newURLTestForTest(provider *urlTestProvider, current C.Proxy, tolerance uint16) *URLTest {
	return &URLTest{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:          "url-test",
			Type:          C.URLTest,
			Providers:     []P.ProxyProvider{provider},
			EmptyFallback: &urlTestProxy{name: "COMPATIBLE"},
		}),
		fastNode:   current,
		tolerance:  tolerance,
		fastSingle: singledo.NewSingle[C.Proxy](time.Second),
	}
}

func (u *URLTest) fastFresh() C.Proxy {
	u.fastSingle.Reset()
	return u.fast(false)
}

func TestURLTestCurrentNodeFirst(t *testing.T) {
	// The current node at index 0 used to be skipped by the loop and so
	// treated as missing, dropping it despite being within tolerance.
	current := &urlTestProxy{name: "current", alive: true, delay: 1000}
	candidate := &urlTestProxy{name: "candidate", alive: true, delay: 100}
	provider := &urlTestProvider{proxies: []C.Proxy{current, candidate}, version: 1}
	if got := newURLTestForTest(provider, current, 1500).fast(false); got != current {
		t.Fatalf("selected %q, want current", got.Name())
	}
}

func TestURLTestProviderUpdate(t *testing.T) {
	for _, currentFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("currentFirst=%v", currentFirst), func(t *testing.T) {
			order := func(current, candidate C.Proxy) []C.Proxy {
				if currentFirst {
					return []C.Proxy{current, candidate}
				}
				return []C.Proxy{candidate, current}
			}

			candidate := &urlTestProxy{name: "candidate", alive: true, delay: 100}
			old := &urlTestProxy{name: "current", alive: true, delay: 1000}
			provider := &urlTestProvider{proxies: order(old, candidate), version: 1}
			group := newURLTestForTest(provider, old, 1500)
			if got := group.fastFresh(); got != old {
				t.Fatalf("initial: selected %q, want current within tolerance", got.Name())
			}

			// Provider update: same name, new instance.
			replacement := &urlTestProxy{name: "current", alive: true, delay: 1000}
			provider.update(order(replacement, candidate)...)
			if got := group.fastFresh(); got != replacement {
				t.Fatalf("after update: selected %q (%p), want rebinding to the new instance %p", got.Name(), got, replacement)
			}

			// Health checks now mark the new instance dead; the old detached
			// instance stays "alive" forever since nothing checks it any more.
			// The group must follow the new instance and fail over.
			replacement.alive = false
			if got := group.fastFresh(); got != candidate {
				t.Fatalf("after failure: selected %q, want failover to candidate", got.Name())
			}
		})
	}
}

func TestURLTestProviderUpdateRemovesCurrent(t *testing.T) {
	candidate := &urlTestProxy{name: "candidate", alive: true, delay: 100}
	old := &urlTestProxy{name: "current", alive: true, delay: 1000}
	provider := &urlTestProvider{proxies: []C.Proxy{old, candidate}, version: 1}
	group := newURLTestForTest(provider, old, 1500)
	group.fastFresh()

	provider.update(&urlTestProxy{name: "candidate", alive: true, delay: 100})
	if got := group.fastFresh(); got.Name() != "candidate" {
		t.Fatalf("selected %q, want candidate after current was removed", got.Name())
	}
}

func TestURLTestToleranceOverflow(t *testing.T) {
	for _, tt := range []struct {
		name           string
		currentDelay   uint16
		candidateDelay uint16
		tolerance      uint16
		wantSwitch     bool
	}{
		{"within tolerance", 1000, 100, 1500, false},
		{"at tolerance boundary", 1600, 100, 1500, false},
		{"above tolerance", 1601, 100, 1500, true},
		// 64500+1500 wraps to 464 in uint16.
		{"sum exceeds uint16", 65000, 64500, 1500, false},
		{"max tolerance", 65000, 100, 0xffff, false},
		// After a provider update every node is alive but unmeasured; the
		// current node must not be dropped for an equally unmeasured one.
		{"all unmeasured", 0xffff, 0xffff, 100, false},
		// A measured node beats an unmeasured current one.
		{"current unmeasured", 0xffff, 100, 100, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			candidate := &urlTestProxy{name: "candidate", alive: true, delay: tt.candidateDelay}
			current := &urlTestProxy{name: "current", alive: true, delay: tt.currentDelay}
			provider := &urlTestProvider{proxies: []C.Proxy{candidate, current}, version: 1}
			want := C.Proxy(current)
			if tt.wantSwitch {
				want = candidate
			}
			if got := newURLTestForTest(provider, current, tt.tolerance).fast(false); got != want {
				t.Fatalf("selected %q, want %q", got.Name(), want.Name())
			}
		})
	}
}

func TestURLTestConcurrentSetAndFast(t *testing.T) {
	var proxies []C.Proxy
	for i := 0; i < 8; i++ {
		proxies = append(proxies, &urlTestProxy{name: fmt.Sprintf("p%d", i), alive: true, delay: uint16(100 + i*10)})
	}
	provider := &urlTestProvider{proxies: proxies, version: 1}
	group := newURLTestForTest(provider, nil, 50)

	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(2)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				name := proxies[(w+i)%len(proxies)].Name()
				if i%5 == 0 {
					group.ForceSet("")
				} else if err := group.Set(name); err != nil {
					t.Error(err)
					return
				}
			}
		}(w)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				// Reset lets several fast() bodies run at once.
				group.fastSingle.Reset()
				if group.fast(i%2 == 0) == nil {
					t.Error("fast returned nil")
					return
				}
				_ = group.Now()
				if _, err := group.MarshalJSON(); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
