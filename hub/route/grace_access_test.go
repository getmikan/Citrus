package route

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/egress"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The "access after a subscription ends" mode of a panel, end to end through
// the controller API: a user moved to grace reaches only the allowed
// destinations (Telegram, the payment page), at a low speed and with a small
// quota; everything else of that user is rejected on the node. The other
// users are not affected. The switch is the one the docs describe (start/
// grace-access): PUT /limits/users, POST /limits/users/reset-quota,
// PUT /rules, DELETE /connections.

// graceConfig is the static part of the node config. The hosts send the test
// domains to the loopback, where the test server listens.
const graceConfig = `
hosts:
  web.telegram.org: 127.0.0.1
  pay.grace.test: 127.0.0.1
  video.grace.test: 127.0.0.1
rule-providers:
  grace-allow:
    type: inline
    behavior: classical
    payload:
      - DOMAIN-SUFFIX,telegram.org
      - DOMAIN-SUFFIX,t.me
      - IP-CIDR,91.108.4.0/22
      - IP-CIDR,149.154.160.0/20
      - DOMAIN,pay.grace.test
rules:
  - MATCH,DIRECT
`

// graceRules are the rules of the node with users in grace.
func graceRules(users ...string) []string {
	if len(users) == 0 {
		return []string{"MATCH,DIRECT"}
	}
	list := strings.Join(users, "/")
	return []string{
		"AND,((IN-USER," + list + "),(RULE-SET,grace-allow,no-resolve)),DIRECT",
		"IN-USER," + list + ",REJECT",
		"MATCH,DIRECT",
	}
}

// graceLimit is the limit of a user in grace: 250 KB/s and a 700 KB quota,
// no expire-at.
const graceLimit = `{"speed-up": "250K", "speed-down": "250K", "quota": "700K"}`

type graceEnv struct {
	t       *testing.T
	h       http.Handler
	inbound string
	proxy   string
	port    uint16
}

func newGraceEnv(t *testing.T) *graceEnv {
	return newGraceEnvConfig(t, graceConfig)
}

func newGraceEnvConfig(t *testing.T, rawConfig string) *graceEnv {
	t.Helper()
	restoreTunnelStatus(t)
	oldSnap, oldRules := tunnel.SnapshotRules(), tunnel.Rules()
	oldHosts, oldEgress := resolver.DefaultHosts, egress.CurrentOptions()
	t.Cleanup(func() {
		tunnel.UpdateProxies(oldSnap.Proxies, oldSnap.Providers)
		tunnel.UpdateRules(oldRules, oldSnap.SubRules, oldSnap.RuleProviders)
		resolver.DefaultHosts = oldHosts
		egress.SetOptions(oldEgress)
	})

	cfg, err := config.Parse([]byte(rawConfig))
	require.NoError(t, err)
	for _, rp := range cfg.RuleProviders {
		require.NoError(t, rp.Initial())
		if c, ok := rp.(io.Closer); ok {
			t.Cleanup(func() { _ = c.Close() })
		}
	}
	tunnel.UpdateProxies(cfg.Proxies, cfg.Providers)
	tunnel.UpdateRules(cfg.Rules, cfg.SubRules, cfg.RuleProviders)
	resolver.DefaultHosts = resolver.NewHosts(cfg.Hosts)
	// the destinations are on the loopback, which the egress guard refuses
	egress.SetOptions(egress.Options{Enable: true, AllowIPs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	tunnel.OnRunning()

	e := &graceEnv{t: t, h: router(false, testSecret, "", Cors{}), inbound: fmt.Sprintf("grace-in-%d", time.Now().UnixNano())}
	in, err := inbound.NewSocks(&inbound.SocksOption{
		BaseOption: inbound.BaseOption{NameStr: e.inbound, Listen: "127.0.0.1", Port: "0"},
		Users:      inbound.AuthUsers{{Username: "alice", Password: "alice-pass"}, {Username: "bob", Password: "bob-pass"}},
	})
	require.NoError(t, err)
	require.NoError(t, in.Listen(tunnel.Tunnel))
	t.Cleanup(func() { _ = in.Close() })
	e.proxy = in.Address()
	e.port = startGraceServer(t)
	t.Cleanup(func() {
		um := statistic.DefaultManager.Users()
		for _, user := range []string{"alice", "bob"} {
			um.DeleteLimit(statistic.UserKey{Inbound: e.inbound, User: user})
		}
	})
	return e
}

// startGraceServer accepts connections that send 8 bytes (the upload and
// download sizes), then the upload; it answers with the download and closes.
func startGraceServer(t *testing.T) uint16 {
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var hdr [8]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint32(hdr[:4]))); err != nil {
					return
				}
				_, _ = c.Write(make([]byte, binary.BigEndian.Uint32(hdr[4:])))
			}()
		}
	}()
	return uint16(ln.Addr().(*stdnet.TCPAddr).Port)
}

func (e *graceEnv) api(method, path, body string) *httptest.ResponseRecorder {
	e.t.Helper()
	path = strings.ReplaceAll(path, "{in}", e.inbound)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testSecret)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	require.Less(e.t, rec.Code, 300, "%s %s: %s", method, path, rec.Body.String())
	return rec
}

func (e *graceEnv) setRules(graceUsers ...string) {
	e.t.Helper()
	e.api(http.MethodPut, "/rules", rulesBody(graceRules(graceUsers...)...))
}

func (e *graceEnv) limitStatus(user string) statistic.UserLimitStatus {
	e.t.Helper()
	var list []statistic.UserLimitStatus
	require.NoError(e.t, json.Unmarshal(e.api(http.MethodGet, "/limits/users?inbound={in}&user="+user, "").Body.Bytes(), &list))
	require.Len(e.t, list, 1)
	return list[0]
}

func (e *graceEnv) stat(user string) statistic.UserStat {
	e.t.Helper()
	s, ok := statistic.DefaultManager.Users().Get(statistic.UserKey{Inbound: e.inbound, User: user})
	require.True(e.t, ok)
	return s
}

// open connects to host (a domain or an IP) through the inbound as user.
func (e *graceEnv) open(user, host string) stdnet.Conn {
	e.t.Helper()
	conn, err := stdnet.DialTimeout("tcp", e.proxy, 5*time.Second)
	require.NoError(e.t, err)
	e.t.Cleanup(func() { _ = conn.Close() })
	target := socks5.ParseAddr(stdnet.JoinHostPort(host, strconv.Itoa(int(e.port))))
	require.NotNil(e.t, target)
	_, err = socks5.ClientHandshake(conn, target, socks5.CmdConnect, &socks5.User{Username: user, Password: user + "-pass"})
	require.NoError(e.t, err)
	return conn
}

// rejected reports whether the node closed conn (a REJECT or a refused
// limit) instead of keeping it open to the server.
func rejected(conn stdnet.Conn) bool {
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	defer conn.SetReadDeadline(time.Time{})
	_, err := conn.Read(make([]byte, 1))
	return err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
}

// transfer moves up bytes up and down bytes down over a new connection to
// host and returns how long it took.
func (e *graceEnv) transfer(user, host string, up, down int) (time.Duration, error) {
	e.t.Helper()
	conn := e.open(user, host)
	defer conn.Close()
	start := time.Now()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(up))
	binary.BigEndian.PutUint32(hdr[4:], uint32(down))
	if _, err := conn.Write(append(hdr[:], make([]byte, up)...)); err != nil {
		return 0, err
	}
	n, err := io.Copy(io.Discard, conn)
	if err == nil && n != int64(down) {
		err = io.ErrUnexpectedEOF
	}
	return time.Since(start), err
}

func (e *graceEnv) reaches(user, host string) bool {
	e.t.Helper()
	_, err := e.transfer(user, host, 100, 1000)
	return err == nil
}

// moveToGrace is the switch of the docs: the grace limit (it replaces the
// paid one, expire-at included), a fresh quota, the rules with the user in
// the grace list, and the user's open connections closed so that they come
// back under the new rules.
func (e *graceEnv) moveToGrace(user string, graceUsers ...string) {
	e.t.Helper()
	e.api(http.MethodPut, "/limits/users?inbound={in}&user="+user, graceLimit)
	e.api(http.MethodPost, "/limits/users/reset-quota?inbound={in}&user="+user, "")
	e.setRules(graceUsers...)
	e.api(http.MethodDelete, "/connections?inbound={in}&user="+user, "")
}

func TestGraceAccessSwitch(t *testing.T) {
	e := newGraceEnv(t)
	const video, telegram, pay = "video.grace.test", "web.telegram.org", "pay.grace.test"

	// paid: bob has a big quota, nobody is in grace
	e.api(http.MethodPut, "/limits/users?inbound={in}&user=bob", `{"quota": "100G"}`)
	_, err := e.transfer("bob", video, 1000, 300_000)
	require.NoError(t, err)
	aliceOpen, bobOpen := e.open("alice", video), e.open("bob", video)
	require.False(t, rejected(aliceOpen))
	require.False(t, rejected(bobOpen))

	// the switch, step by step
	e.api(http.MethodPut, "/limits/users?inbound={in}&user=bob", graceLimit)
	st := e.limitStatus("bob")
	assert.Zero(t, st.ExpireAt)
	assert.Equal(t, int64(250_000), st.SpeedDown)
	assert.GreaterOrEqual(t, st.Used, int64(300_000), "PUT keeps the quota used in the paid period")
	e.api(http.MethodPost, "/limits/users/reset-quota?inbound={in}&user=bob", "")
	assert.Zero(t, e.limitStatus("bob").Used, "so the grace quota starts with a reset")

	e.setRules("bob")
	assert.False(t, rejected(bobOpen), "new rules do not touch the open connections")
	e.api(http.MethodDelete, "/connections?inbound={in}&user=bob", "")
	assert.True(t, rejected(bobOpen), "DELETE /connections closes them")
	assert.False(t, rejected(aliceOpen), "alice's connection stays")

	// grace: only the allowed destinations
	assert.True(t, e.reaches("bob", telegram))
	assert.True(t, e.reaches("bob", pay))
	assert.True(t, rejected(e.open("bob", video)))
	assert.True(t, rejected(e.open("bob", "127.0.0.1")), "an IP outside the allow list too")
	// alice is not affected
	assert.True(t, e.reaches("alice", video))
	assert.True(t, e.reaches("alice", telegram))

	// the grace speed: 400 KB at 250 KB/s takes about 1.6 s, alice is not limited
	elapsed, err := e.transfer("bob", telegram, 0, 400_000)
	require.NoError(t, err)
	t.Logf("bob in grace: 400 KB in %s", elapsed.Round(time.Millisecond))
	assert.Greater(t, elapsed, 1200*time.Millisecond)
	elapsed, err = e.transfer("alice", video, 0, 400_000)
	require.NoError(t, err)
	t.Logf("alice: 400 KB in %s", elapsed.Round(time.Millisecond))
	assert.Less(t, elapsed, time.Second)

	// the grace quota: the transfer that crosses 700 KB is cut, then bob is
	// refused even for Telegram
	_, err = e.transfer("bob", telegram, 0, 1_000_000)
	assert.Error(t, err)
	assert.True(t, e.limitStatus("bob").QuotaExceeded)
	assert.True(t, rejected(e.open("bob", telegram)))
	assert.Positive(t, e.stat("bob").RejectReasons[statistic.RejectQuota])
	assert.True(t, e.reaches("alice", video))

	// paid again: the paid limit, a fresh quota, out of the grace list
	e.api(http.MethodPut, "/limits/users?inbound={in}&user=bob", `{"quota": "100G"}`)
	e.api(http.MethodPost, "/limits/users/reset-quota?inbound={in}&user=bob", "")
	e.setRules()
	assert.True(t, e.reaches("bob", video))
	elapsed, err = e.transfer("bob", video, 0, 400_000)
	require.NoError(t, err)
	assert.Less(t, elapsed, time.Second, "the grace speed is gone")
}

// TestGraceAccessExpireAt shows why the grace mode is not expire-at: the
// expiry is checked after the rules, for every destination, so an expired
// user cannot reach the allowed ones either. The switch replaces the limit
// with one without expire-at.
func TestGraceAccessExpireAt(t *testing.T) {
	e := newGraceEnv(t)
	e.setRules("bob")
	e.api(http.MethodPut, "/limits/users?inbound={in}&user=bob",
		fmt.Sprintf(`{"quota": "100G", "expire-at": %d}`, time.Now().Unix()-1))
	assert.True(t, rejected(e.open("bob", "web.telegram.org")), "expired: even Telegram is refused")
	assert.Positive(t, e.stat("bob").RejectReasons[statistic.RejectExpired])
	assert.True(t, e.reaches("alice", "video.grace.test"))

	e.moveToGrace("bob", "bob")
	assert.False(t, e.limitStatus("bob").Expired)
	assert.True(t, e.reaches("bob", "web.telegram.org"))
	assert.True(t, rejected(e.open("bob", "video.grace.test")))
}

// TestGraceAccessManyUsers keeps a long grace list in the rules: the users
// on it are restricted, the others are not.
func TestGraceAccessManyUsers(t *testing.T) {
	e := newGraceEnv(t)
	users := make([]string, 0, 5001)
	for i := 0; i < 5000; i++ {
		users = append(users, "expired-"+strconv.Itoa(i))
	}
	users = append(users, "bob")
	e.setRules(users...)
	assert.True(t, rejected(e.open("bob", "video.grace.test")))
	assert.True(t, e.reaches("bob", "web.telegram.org"))
	assert.True(t, e.reaches("alice", "video.grace.test"))
}

// TestGraceAccessRuleProvider keeps the grace list in a rule provider
// that the node downloads from the panel: the panel changes the list and
// refreshes the provider; the rules stay as they are.
func TestGraceAccessRuleProvider(t *testing.T) {
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(oldHome) })
	var list atomic.Value
	list.Store("")
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, list.Load().(string))
	}))
	t.Cleanup(panel.Close)

	e := newGraceEnvConfig(t, strings.Replace(graceConfig, "rules:\n  - MATCH,DIRECT\n", `  grace-users:
    type: http
    url: `+panel.URL+`/grace-users.txt
    behavior: classical
    format: text
    interval: 3600
rules:
  - AND,((RULE-SET,grace-users),(RULE-SET,grace-allow,no-resolve)),DIRECT
  - RULE-SET,grace-users,REJECT
  - MATCH,DIRECT
`, 1))
	assert.True(t, e.reaches("bob", "video.grace.test"), "an empty list restricts nobody")

	list.Store("IN-USER,bob\n")
	e.api(http.MethodPut, "/providers/rules/grace-users", "")
	assert.True(t, rejected(e.open("bob", "video.grace.test")))
	assert.True(t, e.reaches("bob", "web.telegram.org"))
	assert.True(t, e.reaches("alice", "video.grace.test"))

	list.Store("# nobody in grace\n")
	e.api(http.MethodPut, "/providers/rules/grace-users", "")
	assert.True(t, e.reaches("bob", "video.grace.test"))
}
