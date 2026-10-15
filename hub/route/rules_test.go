package route

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const putRulesConfig = `
proxies:
  - {name: node-a, type: direct}
proxy-providers:
  pp:
    type: inline
    payload:
      - {name: prov-node, type: direct}
proxy-groups:
  - {name: grp, type: select, use: [pp]}
rule-providers:
  rs:
    type: inline
    behavior: domain
    payload: ['+.ruleset.test']
sub-rules:
  sub1:
    - DOMAIN,sub.test,node-a
rules:
  - DOMAIN,config.test,node-a
  - MATCH,DIRECT
`

// setupPutRules loads putRulesConfig into the tunnel and restores the previous
// state when the test ends.
func setupPutRules(t *testing.T) {
	t.Helper()
	old := tunnel.SnapshotRules()
	oldRules := tunnel.Rules()
	t.Cleanup(func() {
		tunnel.UpdateProxies(old.Proxies, old.Providers)
		tunnel.UpdateRules(oldRules, old.SubRules, old.RuleProviders)
	})

	cfg, err := config.Parse([]byte(putRulesConfig))
	require.NoError(t, err)
	tunnel.UpdateProxies(cfg.Proxies, cfg.Providers)
	tunnel.UpdateRules(cfg.Rules, cfg.SubRules, cfg.RuleProviders)
}

func putRules(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/rules", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func rulesBody(rules ...string) string {
	b, _ := json.Marshal(map[string][]string{"rules": rules})
	return string(b)
}

func rulePayloads() []string {
	var out []string
	for _, r := range tunnel.Rules() {
		out = append(out, r.RuleType().String()+","+r.Payload()+","+r.Adapter())
	}
	return out
}

func TestPutRules(t *testing.T) {
	setupPutRules(t)
	h := router(false, testSecret, "", Cors{})
	configRules := rulePayloads()
	require.Equal(t, []string{"Domain,config.test,node-a", "Match,,DIRECT"}, configRules)

	// the secret is required, as on the other routes
	assert.Equal(t, http.StatusUnauthorized, serveRouter(t, h, http.MethodPut, "/rules", ""))

	// every kind of target the config allows: a proxy, a group of provider
	// proxies, a rule set, a sub-rule and a logic rule
	rec := putRules(t, h, rulesBody(
		"DOMAIN,a.test,node-a",
		"RULE-SET,rs,grp",
		"SUB-RULE,(DOMAIN,x.test),sub1",
		"AND,((DOMAIN,b.test),(NETWORK,tcp)),REJECT",
		"MATCH,DIRECT",
	))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"count": 5, "ephemeral": true}`, rec.Body.String())
	assert.Equal(t, []string{
		"Domain,a.test,node-a",
		"RuleSet,rs,grp",
		"SubRules,(DOMAIN,x.test),sub1",
		"AND,((Domain,b.test) && (Network,tcp)),REJECT",
		"Match,,DIRECT",
	}, rulePayloads())
	for _, r := range tunnel.Rules() {
		_, wrapped := r.(C.RuleWrapper)
		assert.True(t, wrapped, "top level rules are wrapped, so that PATCH /rules/disable works on them")
	}
	replaced := rulePayloads()

	for name, tc := range map[string]struct{ body, err string }{
		"no target":         {rulesBody("DOMAIN,a.test"), "format invalid"},
		"unknown type":      {rulesBody("NOT-A-RULE,a.test,DIRECT"), "rules[0]"},
		"unknown proxy":     {rulesBody("DOMAIN,a.test,DIRECT", "DOMAIN,b.test,nope"), "rules[1] [DOMAIN,b.test,nope] error: proxy [nope] not found"},
		"provider proxy":    {rulesBody("DOMAIN,a.test,prov-node"), "proxy [prov-node] comes from proxy-provider [pp]"},
		"unknown rule set":  {rulesBody("RULE-SET,missing,DIRECT"), "rule set [missing] not found"},
		"unknown sub-rule":  {rulesBody("SUB-RULE,(DOMAIN,x.test),missing"), "sub-rule [missing] not found"},
		"missing rules key": {`{}`, "the rules list is missing"},
		"not json":          {`[`, ""},
	} {
		t.Run(name, func(t *testing.T) {
			rec := putRules(t, h, tc.body)
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), tc.err)
			// a rejected list changes nothing
			assert.Equal(t, replaced, rulePayloads())
		})
	}

	// a body over the limit is refused without being read through
	endless := &endlessReader{}
	req := httptest.NewRequest(http.MethodPut, "/rules", endless)
	req.Header.Set("Authorization", "Bearer "+testSecret)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.LessOrEqual(t, endless.n, int64(2*maxRulesPayload))
	assert.Equal(t, replaced, rulePayloads())

	// an empty list is a valid (if drastic) set of rules
	rec = putRules(t, h, `{"rules": []}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Empty(t, tunnel.Rules())

	// a config reload sets the rules of the config again
	cfg, err := config.Parse([]byte(putRulesConfig))
	require.NoError(t, err)
	tunnel.UpdateProxies(cfg.Proxies, cfg.Providers)
	tunnel.UpdateRules(cfg.Rules, cfg.SubRules, cfg.RuleProviders)
	assert.Equal(t, configRules, rulePayloads())
}

func TestPutRulesEmbedMode(t *testing.T) {
	old := embedMode
	SetEmbedMode(true)
	t.Cleanup(func() { SetEmbedMode(old) })
	h := ruleRouter()
	req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(rulesBody("MATCH,DIRECT")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// TestPutRulesConcurrent swaps the rules while other goroutines read and match
// them, for the race detector.
func TestPutRulesConcurrent(t *testing.T) {
	setupPutRules(t)
	h := router(false, testSecret, "", Cors{})
	bodies := []string{
		rulesBody("DOMAIN,a.test,node-a", "MATCH,DIRECT"),
		rulesBody("DOMAIN,a.test,REJECT", "RULE-SET,rs,grp", "MATCH,DIRECT"),
	}

	require.Equal(t, http.StatusOK, putRules(t, h, bodies[0]).Code)

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			md := &C.Metadata{NetWork: C.TCP, Host: "a.test", DstPort: 443}
			for {
				select {
				case <-stop:
					return
				default:
				}
				rules := tunnel.Rules()
				if !assert.NotEmpty(t, rules) {
					return
				}
				matched, adapter := rules[0].Match(md, C.RuleMatchHelper{})
				assert.True(t, matched)
				assert.Contains(t, []string{"node-a", "REJECT"}, adapter)

				req := httptest.NewRequest(http.MethodGet, "/rules", nil)
				req.Header.Set("Authorization", "Bearer "+testSecret)
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				assert.Equal(t, http.StatusOK, rec.Code)
			}
		}()
	}

	var writers sync.WaitGroup
	for i := 0; i < 2; i++ {
		writers.Add(1)
		go func(i int) {
			defer writers.Done()
			for j := 0; j < 50; j++ {
				rec := putRules(t, h, bodies[(i+j)%2])
				assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			}
		}(i)
	}
	writers.Wait()
	close(stop)
	readers.Wait()
}
