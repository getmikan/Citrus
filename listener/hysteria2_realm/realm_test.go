package hysteria2_realm

import (
	"bufio"
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
	_, base := startRealmListener(t, config)
	return base
}

func startRealmListener(t *testing.T, config LC.Hysteria2RealmServer) (*Listener, string) {
	t.Helper()
	config.Listen = "127.0.0.1:0"
	config.Token = "realm-token"
	if config.RealmNamePattern == "" {
		config.RealmNamePattern = DefaultRealmNamePattern
	}
	l, err := New(config, inbound.NewListenConfig(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l, "http://" + l.AddrList()[0].String()
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

func registerRealm(t *testing.T, base, id string) string {
	t.Helper()
	code, out := realmCall(t, http.MethodPost, base+"/v1/"+id, "realm-token", nil, realmBody)
	require.Equal(t, http.StatusOK, code)
	token, _ := out["session_id"].(string)
	require.NotEmpty(t, token)
	return token
}

// openEvents opens the events stream of the session and returns its body.
func openEvents(t *testing.T, url, token string) io.ReadCloser {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{}).Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp.Body
}

// requireStreamEnds reads the stream to its end, failing if it is still
// open after a few seconds.
func requireStreamEnds(t *testing.T, body io.ReadCloser) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, body)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = body.Close()
		t.Fatal("events stream is still open")
	}
}

// A session holds one events stream: a new one replaces the previous, so a
// reconnecting client is not locked out and streams cannot pile up.
func TestRealmEventsSecondStreamReplacesFirst(t *testing.T) {
	base := startRealm(t, LC.Hysteria2RealmServer{})
	token := registerRealm(t, base, "streams")

	first := openEvents(t, base+"/v1/streams/events", token)
	second := openEvents(t, base+"/v1/streams/events", token)
	requireStreamEnds(t, first)

	// The second stream is the live one: it gets the heartbeat ack.
	code, _ := realmCall(t, http.MethodPost, base+"/v1/streams/heartbeat", token, nil, "")
	require.Equal(t, http.StatusOK, code)
	line := make(chan string, 1)
	go func() {
		r := bufio.NewReader(second)
		s, _ := r.ReadString('\n')
		line <- s
	}()
	select {
	case s := <-line:
		require.Equal(t, "event: heartbeat_ack\n", s)
	case <-time.After(5 * time.Second):
		t.Fatal("no event on the second stream")
	}
}

// Close ends the active events streams, not only the listeners.
func TestRealmCloseEndsEventsStream(t *testing.T) {
	l, base := startRealmListener(t, LC.Hysteria2RealmServer{})
	token := registerRealm(t, base, "closing")

	stream := openEvents(t, base+"/v1/closing/events", token)
	require.NoError(t, l.Close())
	requireStreamEnds(t, stream)
}
