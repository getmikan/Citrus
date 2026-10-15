package route

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func doLimits(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestLimitsREST(t *testing.T) {
	h := router(false, testSecret, "", Cors{})
	um := statistic.DefaultManager.Users()
	t.Cleanup(func() { _ = um.SetConfigLimits(nil) })
	// a fresh inbound per run, so that the test can be repeated (-count)
	in := fmt.Sprintf("rest-lim-%d", time.Now().UnixNano())
	p := func(s string) string { return strings.ReplaceAll(s, "rest-lim", in) }

	assert.Equal(t, http.StatusUnauthorized, serveRouter(t, h, http.MethodGet, "/limits/users", ""))
	assert.Equal(t, http.StatusUnauthorized, serveRouter(t, h, http.MethodPut, "/limits/users?inbound=a&user=b", ""))
	assert.Equal(t, http.StatusUnauthorized, serveRouter(t, h, http.MethodPost, "/limits/users/reset-quota", ""))

	// PUT with units, kebab-case and camelCase keys
	rec := doLimits(t, h, http.MethodPut, p("/limits/users?inbound=rest-lim&user=alice"),
		`{"speed-down": "80Mbps", "speedUp": 1000000, "max-conns": 2, "maxIPs": "3", "quota": "1G", "expire-at": 4102444800}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var st statistic.UserLimitStatus
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &st))
	assert.Equal(t, statistic.UserLimit{
		Inbound: in, User: "alice",
		SpeedUp: 1_000_000, SpeedDown: 10_000_000, MaxConns: 2, MaxIPs: 3,
		Quota: 1_000_000_000, ExpireAt: 4102444800,
	}, st.UserLimit)
	assert.Equal(t, statistic.LimitSourceAPI, st.Source)
	require.NotNil(t, st.Remaining)
	assert.Equal(t, int64(1_000_000_000), *st.Remaining)

	rec = doLimits(t, h, http.MethodPut, p("/limits/users?inbound=rest-lim&user=*"), `{"max-conns": 1}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// bad requests
	for _, tc := range []struct{ path, body string }{
		{p("/limits/users?inbound=rest-lim"), `{}`},
		{p("/limits/users?inbound=rest-lim&user=bob"), `{"quota": "lots"}`},
		{p("/limits/users?inbound=rest-lim&user=bob"), `{"max-conns": -1}`},
		{p("/limits/users?inbound=rest-lim&user=bob"), `{"user": "carol"}`},
		{p("/limits/users?inbound=rest-lim&user=bob"), `{"unknown": 1}`},
		{p("/limits/users?inbound=rest-lim&user=bob"), `not json`},
	} {
		rec = doLimits(t, h, http.MethodPut, tc.path, tc.body)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "%s %s", tc.path, tc.body)
	}

	// a user of the inbound gets the default once it connects
	ip := netip.MustParseAddr("192.0.2.9")
	bob := statistic.UserKey{Inbound: in, User: "bob"}
	c, err := um.Admit(bob, ip)
	require.NoError(t, err)
	defer um.Release(c, ip)
	_, err = um.Admit(bob, ip)
	require.Error(t, err)

	rec = doLimits(t, h, http.MethodGet, p("/limits/users?inbound=rest-lim"), "")
	require.Equal(t, http.StatusOK, rec.Code)
	var list []statistic.UserLimitStatus
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	require.Len(t, list, 3)
	assert.Equal(t, "*", list[0].User)
	assert.Equal(t, "alice", list[1].User)
	assert.Equal(t, "bob", list[2].User)
	assert.True(t, list[2].Inherited)
	assert.Equal(t, int64(1), list[2].MaxConns)

	rec = doLimits(t, h, http.MethodGet, "/limits/users?user=alice", "")
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	require.Len(t, list, 1)

	// the rejection shows in /traffic/users
	stats := getUsers(t, h, p("?inbound=rest-lim&user=bob"))
	require.Len(t, stats, 1)
	assert.Equal(t, int64(1), stats[0].Rejected)
	assert.Equal(t, map[string]int64{statistic.RejectMaxConns: 1}, stats[0].RejectReasons)

	// reset-quota
	l, _ := um.GetLimit(statistic.UserKey{Inbound: in, User: "alice"})
	assert.Equal(t, int64(0), l.Used)
	rec = doLimits(t, h, http.MethodPost, p("/limits/users/reset-quota?inbound=rest-lim"), "")
	require.Equal(t, http.StatusOK, rec.Code)
	var reset struct{ Reset int }
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &reset))
	assert.Equal(t, 2, reset.Reset) // alice and bob

	// DELETE
	assert.Equal(t, http.StatusNoContent, doLimits(t, h, http.MethodDelete, p("/limits/users?inbound=rest-lim&user=*"), "").Code)
	assert.Equal(t, http.StatusNotFound, doLimits(t, h, http.MethodDelete, p("/limits/users?inbound=rest-lim&user=*"), "").Code)
	assert.Equal(t, http.StatusBadRequest, doLimits(t, h, http.MethodDelete, p("/limits/users?inbound=rest-lim"), "").Code)
	c2, err := um.Admit(bob, ip)
	require.NoError(t, err, "bob has no limit any more")
	um.Release(c2, ip)
}
