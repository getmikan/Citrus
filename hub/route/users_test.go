package route

import (
	"encoding/json"
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getUsers(t *testing.T, h http.Handler, query string) []statistic.UserStat {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/traffic/users"+query, nil)
	req.Header.Set("Authorization", "Bearer "+testSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var stats []statistic.UserStat
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &stats))
	return stats
}

func TestTrafficUsers(t *testing.T) {
	h := router(false, testSecret, "", Cors{})
	um := statistic.DefaultManager.Users()
	// the counters are global and cumulative: fresh inbound names keep -count=N runs apart
	restIn, restOther := "rest-in-"+utils.NewUUIDV4().String(), "rest-other-"+utils.NewUUIDV4().String()
	ip := netip.MustParseAddr("192.0.2.1")
	a := um.Acquire(statistic.UserKey{Inbound: restIn, User: "alice"}, ip)
	b := um.Acquire(statistic.UserKey{Inbound: restIn, User: "bob"}, ip)
	o := um.Acquire(statistic.UserKey{Inbound: restOther, User: "alice"}, ip)
	defer um.Release(a, ip)
	defer um.Release(b, ip)
	defer um.Release(o, ip)
	a.AddUp(10)
	a.AddDown(100)
	b.AddUp(1)
	o.AddDown(5)

	assert.Equal(t, http.StatusUnauthorized, serveRouter(t, h, http.MethodGet, "/traffic/users", ""))
	assert.Equal(t, http.StatusBadRequest, serveRouter(t, h, http.MethodGet, "/traffic/users?reset=maybe", testSecret))

	stats := getUsers(t, h, "?inbound="+restIn)
	require.Len(t, stats, 2)
	assert.Equal(t, "alice", stats[0].User)
	assert.Equal(t, int64(10), stats[0].Up)
	assert.Equal(t, int64(100), stats[0].Down)
	assert.Equal(t, int64(1), stats[0].Conns)
	require.Len(t, stats[0].IPs, 1)
	assert.Equal(t, ip, stats[0].IPs[0].IP)
	assert.Equal(t, "bob", stats[1].User)

	stats = getUsers(t, h, "?user=alice")
	var inbounds []string
	for _, s := range stats {
		inbounds = append(inbounds, s.Inbound)
	}
	assert.Contains(t, inbounds, restIn)
	assert.Contains(t, inbounds, restOther)

	// reset drains only the filtered user
	stats = getUsers(t, h, "?inbound="+restIn+"&user=alice&reset=true")
	require.Len(t, stats, 1)
	assert.Equal(t, int64(10), stats[0].Up)
	a.AddUp(2)
	stats = getUsers(t, h, "?inbound="+restIn+"&user=alice&reset=1")
	require.Len(t, stats, 1)
	assert.Equal(t, int64(2), stats[0].Up)
	assert.Equal(t, int64(0), stats[0].Down)
	stats = getUsers(t, h, "?inbound="+restIn+"&user=bob&reset=true")
	assert.Equal(t, int64(1), stats[0].Up, "bob was not drained by alice's reset")
	// without reset the counters stay cumulative
	stats = getUsers(t, h, "?inbound="+restIn+"&user=alice")
	assert.Equal(t, int64(12), stats[0].Up)

	assert.Empty(t, getUsers(t, h, "?inbound=nope"))
}

func TestCloseUserConnections(t *testing.T) {
	h := router(false, testSecret, "", Cors{})
	newTracker := func(inbound, user string) statistic.Tracker {
		local, remote := net.Pipe()
		t.Cleanup(func() { _ = remote.Close() })
		metadata := &C.Metadata{
			NetWork: C.TCP, Type: C.INNER,
			SrcIP: netip.MustParseAddr("192.0.2.2"), SrcPort: 1000,
			DstIP: netip.MustParseAddr("192.0.2.3"), DstPort: 80,
			InName: inbound, InUser: user,
		}
		return statistic.NewTCPTracker(outbound.NewConn(local, outbound.NewDirect()), statistic.DefaultManager, metadata, nil, 0, 0, true)
	}
	alice := newTracker("kick-in", "alice")
	bob := newTracker("kick-in", "bob")
	aliceOther := newTracker("kick-other", "alice")
	defer bob.Close()
	defer aliceOther.Close()

	assert.Equal(t, http.StatusNoContent, serveRouter(t, h, http.MethodDelete, "/connections?inbound=kick-in&user=alice", testSecret))
	assert.Nil(t, statistic.DefaultManager.Get(alice.ID()))
	assert.NotNil(t, statistic.DefaultManager.Get(bob.ID()))
	assert.NotNil(t, statistic.DefaultManager.Get(aliceOther.ID()))
	s, ok := statistic.DefaultManager.Users().Get(statistic.UserKey{Inbound: "kick-in", User: "alice"})
	require.True(t, ok)
	assert.Equal(t, int64(0), s.Conns)

	assert.Equal(t, http.StatusNoContent, serveRouter(t, h, http.MethodDelete, "/connections?user=alice", testSecret))
	assert.Nil(t, statistic.DefaultManager.Get(aliceOther.ID()))
	assert.NotNil(t, statistic.DefaultManager.Get(bob.ID()))
}
