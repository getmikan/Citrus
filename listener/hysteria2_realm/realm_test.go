package hysteria2_realm

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"

	"github.com/stretchr/testify/require"
)

func startRealm(t *testing.T, config LC.Hysteria2RealmServer) string {
	t.Helper()
	config.Listen = "127.0.0.1:0"
	config.Token = "realm-token"
	if config.RealmNamePattern == "" {
		config.RealmNamePattern = DefaultRealmNamePattern
	}
	l, err := New(config, inbound.NewListenConfig(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return "http://" + l.AddrList()[0].String()
}

func realmCall(t *testing.T, method, url, bearer string, header http.Header, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	require.NoError(t, err)
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

const realmBody = `{"addresses":["192.0.2.1:443"]}`

// Without trusted-proxies the forwarding header is not believed: a client
// cannot pass for many addresses to dodge max-realms-per-ip.
func TestRealmIgnoresHeaderWithoutTrustedProxies(t *testing.T) {
	base := startRealm(t, LC.Hysteria2RealmServer{MaxRealmsPerIP: 1, TrustedProxyHeader: "X-Forwarded-For"})

	code, _ := realmCall(t, http.MethodPost, base+"/v1/first", "realm-token", http.Header{"X-Forwarded-For": {"6.6.6.1"}}, realmBody)
	require.Equal(t, http.StatusOK, code)
	code, _ = realmCall(t, http.MethodPost, base+"/v1/second", "realm-token", http.Header{"X-Forwarded-For": {"6.6.6.2"}}, realmBody)
	require.Equal(t, http.StatusTooManyRequests, code, "a forged X-Forwarded-For dodged the per-IP limit")
}

// From a trusted proxy the header still names the client.
func TestRealmBelievesHeaderFromTrustedProxy(t *testing.T) {
	base := startRealm(t, LC.Hysteria2RealmServer{MaxRealmsPerIP: 1, TrustedProxyHeader: "X-Forwarded-For", TrustedProxies: []string{"loopback"}})

	code, _ := realmCall(t, http.MethodPost, base+"/v1/first", "realm-token", http.Header{"X-Forwarded-For": {"203.0.113.1"}}, realmBody)
	require.Equal(t, http.StatusOK, code)
	code, _ = realmCall(t, http.MethodPost, base+"/v1/second", "realm-token", http.Header{"X-Forwarded-For": {"203.0.113.2"}}, realmBody)
	require.Equal(t, http.StatusOK, code)
}

// The session ID is a bearer token: it never reaches the log subscribers.
func TestRealmLogsNoSessionToken(t *testing.T) {
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	base := startRealm(t, LC.Hysteria2RealmServer{})

	code, out := realmCall(t, http.MethodPost, base+"/v1/logged", "realm-token", nil, realmBody)
	require.Equal(t, http.StatusOK, code)
	token, _ := out["session_id"].(string)
	require.NotEmpty(t, token)
	code, _ = realmCall(t, http.MethodPost, base+"/v1/logged/heartbeat", token, nil, "")
	require.Equal(t, http.StatusOK, code)
	code, _ = realmCall(t, http.MethodDelete, base+"/v1/logged", token, nil, "")
	require.Equal(t, http.StatusNoContent, code)

	var logged []string
	deadline := time.After(time.Second)
collect:
	for {
		select {
		case event := <-sub:
			logged = append(logged, event.Payload)
		case <-deadline:
			break collect
		}
	}
	all := strings.Join(logged, "\n")
	require.Contains(t, all, "registered realm=logged session="+sessionLogID(token))
	require.NotContains(t, all, token)
}
