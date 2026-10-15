package tunnel

import (
	"sync"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// namedProxy is the part of a proxy that match uses.
type namedProxy struct {
	C.Proxy
	name string
}

func (p namedProxy) Name() string                     { return p.name }
func (p namedProxy) Type() C.AdapterType              { return C.Direct }
func (p namedProxy) SupportUDP() bool                 { return true }
func (p namedProxy) Unwrap(*C.Metadata, bool) C.Proxy { return nil }

func setupReplaceRules(t *testing.T) {
	t.Helper()
	old := SnapshotRules()
	oldRules := Rules()
	t.Cleanup(func() {
		UpdateProxies(old.Proxies, old.Providers)
		UpdateRules(oldRules, old.SubRules, old.RuleProviders)
	})
	UpdateProxies(map[string]C.Proxy{
		"DIRECT": namedProxy{name: "DIRECT"},
		"REJECT": namedProxy{name: "REJECT"},
	}, nil)
	UpdateRules([]C.Rule{RC.NewDomain("a.test", "DIRECT")}, nil, nil)
}

func TestReplaceRulesStaleSnapshot(t *testing.T) {
	setupReplaceRules(t)

	snap := SnapshotRules()
	require.NoError(t, ReplaceRules(snap, []C.Rule{RC.NewDomain("a.test", "REJECT")}))
	// replacing the rules does not invalidate the snapshot of the proxies
	require.NoError(t, ReplaceRules(snap, []C.Rule{RC.NewDomain("b.test", "REJECT")}))
	assert.Equal(t, "b.test", Rules()[0].Payload())

	// a reload in between: the rules parsed against the old proxies are dropped
	UpdateProxies(snap.Proxies, snap.Providers)
	assert.ErrorIs(t, ReplaceRules(snap, []C.Rule{RC.NewDomain("c.test", "REJECT")}), ErrRulesChanged)
	snap = SnapshotRules()
	UpdateRules(Rules(), nil, nil)
	assert.ErrorIs(t, ReplaceRules(snap, []C.Rule{RC.NewDomain("c.test", "REJECT")}), ErrRulesChanged)
	assert.Equal(t, "b.test", Rules()[0].Payload())
}

// TestReplaceRulesWhileMatching matches connections while the rules are swapped;
// every match sees either the old or the new list, never a mix (run with -race).
func TestReplaceRulesWhileMatching(t *testing.T) {
	setupReplaceRules(t)
	sets := [][]C.Rule{
		{RC.NewDomain("a.test", "DIRECT")},
		{RC.NewDomain("a.test", "REJECT")},
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				md := &C.Metadata{NetWork: C.TCP, Host: "a.test", DstPort: 443}
				proxy, rule, err := match(md, C.RuleMatchHelper{})
				if !assert.NoError(t, err) || !assert.NotNil(t, rule) {
					return
				}
				assert.Equal(t, rule.Adapter(), proxy.Name())
			}
		}()
	}
	for i := 0; i < 200; i++ {
		require.NoError(t, ReplaceRules(SnapshotRules(), sets[i%2]))
	}
	close(stop)
	wg.Wait()
}
