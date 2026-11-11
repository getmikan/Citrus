package statistic

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseUnits(t *testing.T) {
	sizes := map[string]int64{
		"0":      0,
		"1024":   1024,
		"10K":    10_000,
		"10KB":   10_000,
		"10k":    10_000,
		"1.5G":   1_500_000_000,
		"100G":   100_000_000_000,
		"100 GB": 100_000_000_000,
		"1T":     1_000_000_000_000,
		"1KiB":   1024,
		"512MiB": 512 << 20,
		"2Gi":    2 << 30,
		"7B":     7,
	}
	for s, want := range sizes {
		got, err := ParseSize(s)
		require.NoError(t, err, s)
		assert.Equal(t, want, got, s)
	}
	for _, s := range []string{"10Mbps", "10MB/s", "-1", "abc", "10X", "1.5.5G", "10Mb"} {
		_, err := ParseSize(s)
		assert.Error(t, err, s)
	}

	rates := map[string]int64{
		"10M":     10_000_000,
		"10MB/s":  10_000_000,
		"10MBps":  10_000_000,
		"80Mbps":  10_000_000,
		"80Mb":    10_000_000,
		"80 Mbps": 10_000_000,
		"1Gbps":   125_000_000,
		"1MiB/s":  1 << 20,
		"4096":    4096,
	}
	for s, want := range rates {
		got, err := ParseRate(s)
		require.NoError(t, err, s)
		assert.Equal(t, want, got, s)
	}

	n, err := ParseSize(1000) // a YAML or JSON number
	require.NoError(t, err)
	assert.Equal(t, int64(1000), n)
	n, err = ParseRate(float64(2e6))
	require.NoError(t, err)
	assert.Equal(t, int64(2_000_000), n)
	_, err = ParseRate(1.5)
	assert.Error(t, err)
}

func TestParseUserLimit(t *testing.T) {
	l, err := ParseUserLimit(map[string]any{
		"inbound": "vless-in", "user": "alice",
		"speed-up": "10M", "speed-down": "80Mbps",
		"max-conns": 64, "max-ips": 3,
		"quota": "100G", "expire-at": 1767225600,
	})
	require.NoError(t, err)
	assert.Equal(t, UserLimit{
		Inbound: "vless-in", User: "alice",
		SpeedUp: 10_000_000, SpeedDown: 10_000_000,
		MaxConns: 64, MaxIPs: 3,
		Quota: 100_000_000_000, ExpireAt: 1767225600,
	}, l)

	l, err = ParseUserLimit(map[string]any{"inbound": "in", "user": "a", "speed-group": "user-7", "speed-up": "1M"})
	require.NoError(t, err)
	assert.Equal(t, "user-7", l.SpeedGroup)

	// camelCase keys and an RFC 3339 time
	l, err = ParseUserLimit(map[string]any{"inbound": "in", "user": "*", "maxConns": "2", "expireAt": "2026-01-01T00:00:00Z"})
	require.NoError(t, err)
	assert.Equal(t, int64(2), l.MaxConns)
	assert.Equal(t, int64(1767225600), l.ExpireAt)

	for _, m := range []map[string]any{
		{"user": "alice"},
		{"inbound": "in"},
		{"inbound": "in", "user": "a", "quota": "10Mbps"},
		{"inbound": "in", "user": "a", "max-conns": -1},
		{"inbound": "in", "user": "a", "max-conns": "many"},
		{"inbound": "in", "user": "a", "speed": "1M"},
		{"inbound": "in", "user": "a", "expire-at": "tomorrow-ish"},
		{"inbound": "in", "user": "a", "speed-group": strings.Repeat("g", 257)},
	} {
		_, err := ParseUserLimit(m)
		assert.Error(t, err, "%v", m)
	}
}

func rejectReason(t *testing.T, err error) string {
	t.Helper()
	var le *LimitError
	require.True(t, errors.As(err, &le), "want a LimitError, got %v", err)
	return le.Reason
}

func TestLimitMaxConns(t *testing.T) {
	um, _ := newTestUserManager()
	require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", MaxConns: 2}))

	a1, err := um.Admit(keyA, ip1)
	require.NoError(t, err)
	_, err = um.Admit(keyA, ip2)
	require.NoError(t, err)
	_, err = um.Admit(keyA, ip1)
	assert.Equal(t, RejectMaxConns, rejectReason(t, err))
	// another user is not limited
	for i := 0; i < 5; i++ {
		_, err = um.Admit(keyB, ip1)
		require.NoError(t, err)
	}
	um.Release(a1, ip1)
	_, err = um.Admit(keyA, ip1)
	require.NoError(t, err)

	s, _ := um.Get(keyA)
	assert.Equal(t, int64(2), s.Conns)
	assert.Equal(t, int64(1), s.Rejected)
	assert.Equal(t, map[string]int64{RejectMaxConns: 1}, s.RejectReasons)

	// Acquire (trackers outside the tunnel) does not check
	assert.NotNil(t, um.Acquire(keyA, ip1))
}

func TestLimitMaxIPs(t *testing.T) {
	um, clock := newTestUserManager()
	require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", MaxIPs: 2}))
	ip3 := netip.MustParseAddr("10.0.0.3")

	c1, err := um.Admit(keyA, ip1)
	require.NoError(t, err)
	_, err = um.Admit(keyA, ip2)
	require.NoError(t, err)
	_, err = um.Admit(keyA, ip3)
	assert.Equal(t, RejectMaxIPs, rejectReason(t, err))
	// a known address keeps working
	_, err = um.Admit(keyA, ip1)
	require.NoError(t, err)

	// ip1 goes offline, but stays online for the release window
	um.Release(c1, ip1)
	um.Release(c1, ip1)
	_, err = um.Admit(keyA, ip3)
	assert.Equal(t, RejectMaxIPs, rejectReason(t, err))
	clock.advance(um.IPRelease + time.Second)
	_, err = um.Admit(keyA, ip3)
	require.NoError(t, err)
	// and now ip1 is the new one
	_, err = um.Admit(keyA, ip1)
	assert.Equal(t, RejectMaxIPs, rejectReason(t, err))
}

func TestLimitQuota(t *testing.T) {
	um, _ := newTestUserManager()
	closed := make(chan UserKey, 4)
	um.SetCloser(func(k UserKey, _ func() bool) { closed <- k })
	require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", Quota: 1000}))

	c, err := um.Admit(keyA, ip1)
	require.NoError(t, err)
	l := c.limit.Load()
	require.NotNil(t, l)
	l.addUp(600, nil)
	st, ok := um.GetLimit(keyA)
	require.True(t, ok)
	require.NotNil(t, st.Remaining)
	assert.Equal(t, int64(400), *st.Remaining)
	assert.False(t, st.QuotaExceeded)

	l.addDown(500, nil)
	select {
	case k := <-closed:
		assert.Equal(t, keyA, k)
	case <-time.After(time.Second):
		t.Fatal("the connections of the user were not closed")
	}
	_, err = um.Admit(keyA, ip1)
	assert.Equal(t, RejectQuota, rejectReason(t, err))
	st, _ = um.GetLimit(keyA)
	assert.True(t, st.QuotaExceeded)
	assert.Equal(t, int64(0), *st.Remaining)
	assert.Equal(t, int64(1100), st.Used)

	// reset
	assert.Equal(t, 1, um.ResetQuota(func(k UserKey) bool { return k == keyA }))
	_, err = um.Admit(keyA, ip1)
	require.NoError(t, err)
	st, _ = um.GetLimit(keyA)
	assert.Equal(t, int64(0), st.Used)

	// over the quota again, then the quota is raised
	l.addUp(2000, nil)
	<-closed
	_, err = um.Admit(keyA, ip1)
	assert.Equal(t, RejectQuota, rejectReason(t, err))
	require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", Quota: 5000}))
	_, err = um.Admit(keyA, ip1)
	require.NoError(t, err)
	st, _ = um.GetLimit(keyA)
	assert.Equal(t, int64(2000), st.Used, "the usage survives a change of the limit")
	assert.Equal(t, int64(3000), *st.Remaining)

	// lowering the quota under the usage closes the connections
	require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", Quota: 1500}))
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("lowering the quota did not close the connections")
	}
}

func TestLimitExpire(t *testing.T) {
	um, clock := newTestUserManager()
	exp := clock.now().Unix() + 10
	require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", ExpireAt: exp}))
	_, err := um.Admit(keyA, ip1)
	require.NoError(t, err)
	clock.advance(11 * time.Second)
	_, err = um.Admit(keyA, ip1)
	assert.Equal(t, RejectExpired, rejectReason(t, err))
	st, _ := um.GetLimit(keyA)
	assert.True(t, st.Expired)

	// the expiry closes the open connections on time (real clock). ExpireAt has a one-second
	// resolution: two seconds ahead keeps it at least a second away from now, so the Admit
	// below cannot land on the far side of a second boundary.
	real := NewUserManager()
	closed := make(chan UserKey, 1)
	real.SetCloser(func(k UserKey, _ func() bool) { closed <- k })
	expireAt := time.Unix(time.Now().Unix()+2, 0)
	require.NoError(t, real.SetLimit(UserLimit{Inbound: "in", User: "alice", ExpireAt: expireAt.Unix()}))
	_, err = real.Admit(keyA, ip1)
	require.NoError(t, err)
	select {
	case <-closed:
		now := time.Now()
		assert.False(t, now.Before(expireAt), "closed %s before expire-at", expireAt.Sub(now))
		assert.WithinDuration(t, expireAt, now, time.Second)
	case <-time.After(5 * time.Second):
		t.Fatal("the user was not closed at expire-at")
	}
	_, err = real.Admit(keyA, ip1)
	assert.Equal(t, RejectExpired, rejectReason(t, err))
}

func TestLimitDefaultsAndReload(t *testing.T) {
	um, _ := newTestUserManager()
	require.NoError(t, um.SetConfigLimits([]UserLimit{
		{Inbound: "in", User: AnyUser, MaxConns: 1, Quota: 100},
		{Inbound: "in", User: "alice", MaxConns: 2, SpeedDown: 1000},
	}))
	// bob inherits the default, alice has her own
	_, err := um.Admit(keyB, ip1)
	require.NoError(t, err)
	_, err = um.Admit(keyB, ip1)
	assert.Equal(t, RejectMaxConns, rejectReason(t, err))
	ca, err := um.Admit(keyA, ip1)
	require.NoError(t, err)
	_, err = um.Admit(keyA, ip1)
	require.NoError(t, err)

	st, ok := um.GetLimit(keyB)
	require.True(t, ok)
	assert.True(t, st.Inherited)
	assert.Equal(t, "", st.Source)
	st, _ = um.GetLimit(keyA)
	assert.False(t, st.Inherited)
	assert.Equal(t, LimitSourceConfig, st.Source)

	all := um.Limits()
	require.Len(t, all, 3) // "*", alice, bob
	assert.Equal(t, AnyUser, all[0].User)

	// an API limit; a reload with the same config drops it and keeps the state
	la := ca.limit.Load()
	bucket := la.downBucket()
	la.charge(42)
	require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "carol", MaxConns: 9}))
	_, ok = um.GetLimit(UserKey{Inbound: "in", User: "carol"})
	require.True(t, ok)
	require.NoError(t, um.SetConfigLimits([]UserLimit{
		{Inbound: "in", User: AnyUser, MaxConns: 1, Quota: 100},
		{Inbound: "in", User: "alice", MaxConns: 2, SpeedDown: 1000},
	}))
	st, _ = um.GetLimit(UserKey{Inbound: "in", User: "carol"})
	assert.True(t, st.Inherited, "carol falls back to the default after the reload")
	assert.Same(t, la, ca.limit.Load())
	assert.Same(t, bucket, la.downBucket(), "an unchanged speed keeps its bucket")
	st, _ = um.GetLimit(keyA)
	assert.Equal(t, int64(42), st.Used)

	// no limit at all: the counters have a nil limit again
	require.NoError(t, um.SetConfigLimits(nil))
	assert.Nil(t, ca.limit.Load())
	assert.Empty(t, um.Limits())
	assert.False(t, um.limitsOn.Load())
	_, err = um.Admit(keyB, ip1)
	require.NoError(t, err)

	// duplicates and invalid limits are refused
	assert.Error(t, um.SetConfigLimits([]UserLimit{{Inbound: "in", User: "a"}, {Inbound: "in", User: "a"}}))
	assert.Error(t, um.SetLimit(UserLimit{Inbound: "in"}))
	assert.True(t, um.DeleteLimit(UserKey{Inbound: "x", User: "y"}) == false)
}

func TestLimitSweepPrunesInheritedState(t *testing.T) {
	um, clock := newTestUserManager()
	require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: AnyUser, SpeedDown: 1000}))
	require.NoError(t, um.SetLimit(UserLimit{Inbound: "quota", User: AnyUser, Quota: 1000}))
	keyQ := UserKey{Inbound: "quota", User: "bob"}
	for _, k := range []UserKey{keyB, keyQ} {
		c, err := um.Admit(k, ip1)
		require.NoError(t, err)
		um.Release(c, ip1)
	}
	um.Drain()
	clock.advance(um.IdleTTL + time.Minute)
	um.Sweep()
	_, ok := um.Get(keyB)
	require.False(t, ok)
	um.lmu.Lock()
	_, speedKept := um.lstates[keyB]
	_, quotaKept := um.lstates[keyQ]
	um.lmu.Unlock()
	assert.False(t, speedKept, "an inherited speed limit is dropped with the counter")
	assert.True(t, quotaKept, "a quota usage is kept")
}

func TestLimitDeleteFallsBackToDefault(t *testing.T) {
	um, _ := newTestUserManager()
	require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: AnyUser, MaxConns: 1}))
	require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", MaxConns: 5}))
	c, err := um.Admit(keyA, ip1)
	require.NoError(t, err)
	assert.True(t, um.DeleteLimit(keyA))
	_, err = um.Admit(keyA, ip1)
	assert.Equal(t, RejectMaxConns, rejectReason(t, err))
	assert.True(t, um.DeleteLimit(UserKey{Inbound: "in", User: AnyUser}))
	assert.Nil(t, c.limit.Load())
	_, err = um.Admit(keyA, ip1)
	require.NoError(t, err)
}

func TestTokenBucket(t *testing.T) {
	const rate = 1_000_000
	b := newTokenBucket(rate)
	now := int64(10 * time.Second)
	clock := func() int64 { return now }
	// the burst is free, then every 100 000 bytes cost 100 ms
	assert.Equal(t, time.Duration(0), b.takeAt(50_000, clock))
	var debt time.Duration
	for i := 0; i < 10; i++ {
		debt = b.takeAt(100_000, clock)
	}
	// 1 050 000 bytes at 1 MB/s with 100 ms of burst: 950 ms of debt
	assert.Equal(t, 950*time.Millisecond, debt)
	// after waiting it off, the next take costs only itself
	now += int64(debt)
	assert.Equal(t, 100*time.Millisecond, b.takeAt(100_000, clock))
	// idle for long: the burst is back, no more
	now += int64(time.Hour)
	assert.Equal(t, time.Duration(0), b.takeAt(100_000, clock))
	assert.Equal(t, 100*time.Millisecond, b.takeAt(100_000, clock))
	assert.Nil(t, newTokenBucket(0))
}

func TestTokenBucketConcurrent(t *testing.T) {
	const rate = 2_000_000
	b := newTokenBucket(rate)
	start := time.Now()
	var wg sync.WaitGroup
	var moved atomic.Int64
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				waitClosed(b.take(10_000), nil)
				moved.Add(10_000)
			}
		}()
	}
	wg.Wait()
	// 4 MB at 2 MB/s, minus the 100 ms burst
	elapsed := time.Since(start)
	want := time.Duration(float64(moved.Load())/rate*float64(time.Second)) - limitBurst
	assert.InDelta(t, float64(want), float64(elapsed), float64(want)/10, "elapsed %s, want %s", elapsed, want)
}

func TestWaitClosedWakesUp(t *testing.T) {
	var closed atomic.Bool
	go func() {
		time.Sleep(100 * time.Millisecond)
		closed.Store(true)
	}()
	start := time.Now()
	waitClosed(10*time.Second, &closed)
	assert.Less(t, time.Since(start), time.Second)
}

func TestRejectLogThrottle(t *testing.T) {
	um, clock := newTestUserManager()
	require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", ExpireAt: 1}))
	var le *LimitError
	_, err := um.Admit(keyA, ip1)
	require.True(t, errors.As(err, &le))
	assert.False(t, le.Quiet)
	for i := 0; i < 3; i++ {
		_, err = um.Admit(keyA, ip1)
		require.True(t, errors.As(err, &le))
		assert.True(t, le.Quiet)
	}
	clock.advance(2 * time.Second)
	_, err = um.Admit(keyA, ip1)
	require.True(t, errors.As(err, &le))
	assert.False(t, le.Quiet)
	assert.Equal(t, int64(3), le.Suppressed)
	s, _ := um.Get(keyA)
	assert.Equal(t, int64(5), s.Rejected)
	assert.Equal(t, int64(5), s.RejectReasons[RejectExpired])
}

// gatedCloser is a closer that holds each pass until released and reports
// what still returned when the pass ran.
func gatedCloser(um *UserManager) (started <-chan UserKey, release func() bool) {
	st := make(chan UserKey, 1)
	rel := make(chan struct{})
	res := make(chan bool, 1)
	um.SetCloser(func(k UserKey, still func() bool) {
		st <- k
		<-rel
		res <- still()
	})
	return st, func() bool {
		rel <- struct{}{}
		return <-res
	}
}

func waitStarted(t *testing.T, started <-chan UserKey) {
	t.Helper()
	select {
	case k := <-started:
		assert.Equal(t, keyA, k)
	case <-time.After(time.Second):
		t.Fatal("the connections of the user were not closed")
	}
}

// TestLimitLateClose checks that a pass closing the connections of a user
// that runs late does not close anything once the reason for it is gone.
func TestLimitLateClose(t *testing.T) {
	t.Run("quota still used up", func(t *testing.T) {
		um, _ := newTestUserManager()
		started, release := gatedCloser(um)
		require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", Quota: 1000}))
		c, err := um.Admit(keyA, ip1)
		require.NoError(t, err)
		c.limit.Load().addUp(1500, nil)
		waitStarted(t, started)
		assert.True(t, release())
	})
	t.Run("quota reset", func(t *testing.T) {
		um, _ := newTestUserManager()
		started, release := gatedCloser(um)
		require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", Quota: 1000}))
		c, err := um.Admit(keyA, ip1)
		require.NoError(t, err)
		c.limit.Load().addUp(1500, nil)
		waitStarted(t, started)
		um.ResetQuota(nil)
		assert.False(t, release())
	})
	t.Run("quota raised", func(t *testing.T) {
		um, _ := newTestUserManager()
		started, release := gatedCloser(um)
		require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", Quota: 1000}))
		c, err := um.Admit(keyA, ip1)
		require.NoError(t, err)
		c.limit.Load().addUp(1500, nil)
		waitStarted(t, started)
		require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", Quota: 5000}))
		assert.False(t, release())
	})
	t.Run("limit removed", func(t *testing.T) {
		um, _ := newTestUserManager()
		started, release := gatedCloser(um)
		require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", Quota: 1000}))
		c, err := um.Admit(keyA, ip1)
		require.NoError(t, err)
		c.limit.Load().addUp(1500, nil)
		waitStarted(t, started)
		um.DeleteLimit(keyA)
		assert.False(t, release())
	})
	t.Run("expiry moved", func(t *testing.T) {
		um, clock := newTestUserManager()
		started, release := gatedCloser(um)
		require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", ExpireAt: clock.now().Unix() - 1}))
		waitStarted(t, started)
		require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", ExpireAt: clock.now().Unix() + 3600}))
		assert.False(t, release())
	})
	t.Run("still expired", func(t *testing.T) {
		um, clock := newTestUserManager()
		started, release := gatedCloser(um)
		require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", ExpireAt: clock.now().Unix() - 1}))
		waitStarted(t, started)
		assert.True(t, release())
	})
}

func TestTokenBucketRetune(t *testing.T) {
	b := newTokenBucket(1_000_000)
	now := int64(10 * time.Second)
	clock := func() int64 { return now }
	// 1 100 000 bytes at 1 MB/s with 100 ms of burst: 1 s of debt
	assert.Equal(t, time.Second, b.takeAt(1_100_000, clock))
	// a new rate keeps the debt and prices what comes next at the new rate
	b.setRate(2_000_000)
	assert.Equal(t, time.Second+50*time.Millisecond, b.takeAt(100_000, clock))
}

func TestLimitSpeedGroup(t *testing.T) {
	um, _ := newTestUserManager()
	other := UserKey{Inbound: "other-in", User: "bob"}
	require.NoError(t, um.SetLimit(UserLimit{Inbound: keyA.Inbound, User: keyA.User, SpeedUp: 1_000_000, SpeedDown: 2_000_000, SpeedGroup: "g"}))
	require.NoError(t, um.SetLimit(UserLimit{Inbound: other.Inbound, User: other.User, SpeedUp: 1_000_000, SpeedDown: 2_000_000, SpeedGroup: "g", Quota: 1 << 30}))
	a, err := um.Admit(keyA, ip1)
	require.NoError(t, err)
	b, err := um.Admit(other, ip1)
	require.NoError(t, err)
	la, lb := a.limit.Load(), b.limit.Load()
	// users of one group, on any inbounds, take from the same buckets
	require.NotNil(t, la.upBucket())
	assert.Same(t, la.upBucket(), lb.upBucket())
	assert.Same(t, la.downBucket(), lb.downBucket())
	// the quota stays the user's own
	assert.False(t, la.hasQuota())
	assert.True(t, lb.hasQuota())

	// a new speed retunes the buckets in place: the debt of the group is kept
	up := la.upBucket()
	for _, k := range []UserKey{keyA, other} {
		require.NoError(t, um.SetLimit(UserLimit{Inbound: k.Inbound, User: k.User, SpeedUp: 3_000_000, SpeedDown: 2_000_000, SpeedGroup: "g"}))
	}
	assert.Same(t, up, la.upBucket())
	assert.Equal(t, int64(3_000_000), up.rate.Load())

	// out of the group, a user has buckets of its own
	require.NoError(t, um.SetLimit(UserLimit{Inbound: other.Inbound, User: other.User, SpeedUp: 3_000_000}))
	assert.NotSame(t, la.upBucket(), lb.upBucket())
	assert.Nil(t, lb.downBucket())

	// a group no user is in any more is dropped
	assert.True(t, um.DeleteLimit(keyA))
	um.lmu.Lock()
	assert.Empty(t, um.sgroups)
	um.lmu.Unlock()
}

func TestLimitOwnSpeedRetunedInPlace(t *testing.T) {
	um, _ := newTestUserManager()
	require.NoError(t, um.SetLimit(UserLimit{Inbound: keyA.Inbound, User: keyA.User, SpeedUp: 1_000_000}))
	a, err := um.Admit(keyA, ip1)
	require.NoError(t, err)
	up := a.limit.Load().upBucket()
	require.NoError(t, um.SetLimit(UserLimit{Inbound: keyA.Inbound, User: keyA.User, SpeedUp: 5_000_000}))
	assert.Same(t, up, a.limit.Load().upBucket())
	assert.Equal(t, int64(5_000_000), up.rate.Load())
	require.NoError(t, um.SetLimit(UserLimit{Inbound: keyA.Inbound, User: keyA.User, Quota: 1 << 20}))
	assert.Nil(t, a.limit.Load().upBucket())
}

func TestSetLimits(t *testing.T) {
	um, _ := newTestUserManager()
	require.NoError(t, um.SetLimit(UserLimit{Inbound: keyA.Inbound, User: keyA.User, MaxConns: 1}))
	require.NoError(t, um.SetLimits([]UserLimit{
		{Inbound: keyB.Inbound, User: keyB.User, Quota: 1000},
		{Inbound: "in2", User: "carol", SpeedUp: 1000},
	}, []UserKey{keyA}))
	_, own := um.GetLimit(keyA)
	assert.False(t, own)
	s, ok := um.GetLimit(keyB)
	require.True(t, ok)
	assert.Equal(t, int64(1000), s.Quota)
	assert.Equal(t, LimitSourceAPI, s.Source)

	// one bad limit and nothing changes
	err := um.SetLimits([]UserLimit{{Inbound: "in2", User: "dave", Quota: 5}, {Inbound: "in2", User: "erin", Quota: -1}}, []UserKey{keyB})
	assert.Error(t, err)
	_, ok = um.GetLimit(keyB)
	assert.True(t, ok)
	_, ok = um.GetLimit(UserKey{Inbound: "in2", User: "dave"})
	assert.False(t, ok)
}
