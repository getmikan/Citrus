package statistic

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestUserManager() (*UserManager, *fakeClock) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	um := NewUserManager()
	um.now = clock.now
	return um, clock
}

var (
	keyA = UserKey{Inbound: "in", User: "alice"}
	keyB = UserKey{Inbound: "in", User: "bob"}
	ip1  = netip.MustParseAddr("10.0.0.1")
	ip2  = netip.MustParseAddr("10.0.0.2")
)

func TestUserCounterMath(t *testing.T) {
	um, _ := newTestUserManager()
	a := um.Acquire(keyA, ip1)
	b := um.Acquire(keyB, ip2)
	a.AddUp(100)
	a.AddDown(1000)
	a.AddUp(5)
	b.AddDown(7)

	s, ok := um.Get(keyA)
	require.True(t, ok)
	assert.Equal(t, int64(105), s.Up)
	assert.Equal(t, int64(1000), s.Down)
	assert.Equal(t, int64(1), s.Conns)
	assert.Equal(t, []UserIP{{IP: ip1, Conns: 1, LastSeen: s.IPs[0].LastSeen}}, s.IPs)

	stats := um.Snapshot()
	require.Len(t, stats, 2)
	assert.Equal(t, "alice", stats[0].User)
	assert.Equal(t, "bob", stats[1].User)
	assert.Equal(t, int64(7), stats[1].Down)

	// a second connection of the same user from the same address shares the counter
	a2 := um.Acquire(keyA, ip1)
	assert.Same(t, a, a2)
	s, _ = um.Get(keyA)
	assert.Equal(t, int64(2), s.Conns)
	assert.Equal(t, int64(2), s.IPs[0].Conns)

	um.Release(a2, ip1)
	um.Release(a, ip1)
	s, _ = um.Get(keyA)
	assert.Equal(t, int64(0), s.Conns)
	require.Len(t, s.IPs, 1) // kept for the release window
	assert.Equal(t, int64(0), s.IPs[0].Conns)

	_, ok = um.Get(UserKey{Inbound: "in", User: "nobody"})
	assert.False(t, ok)
}

func TestUserDrain(t *testing.T) {
	um, _ := newTestUserManager()
	a := um.Acquire(keyA, ip1)
	b := um.Acquire(keyB, ip1)
	a.AddUp(10)
	a.AddDown(20)
	b.AddUp(1)

	// a filtered drain resets only the matching user
	d := um.DrainFunc(func(k UserKey) bool { return k == keyA })
	require.Len(t, d, 1)
	assert.Equal(t, int64(10), d[0].Up)
	assert.Equal(t, int64(20), d[0].Down)

	a.AddUp(3)
	d = um.Drain()
	require.Len(t, d, 2)
	assert.Equal(t, int64(3), d[0].Up)
	assert.Equal(t, int64(0), d[0].Down)
	assert.Equal(t, int64(1), d[1].Up)

	d = um.Drain()
	assert.Equal(t, int64(0), d[0].Up+d[0].Down+d[1].Up+d[1].Down)

	// the snapshot stays cumulative
	s, _ := um.Get(keyA)
	assert.Equal(t, int64(13), s.Up)
	assert.Equal(t, int64(20), s.Down)
}

func TestUserDrainConcurrent(t *testing.T) {
	um, _ := newTestUserManager()
	const writers, perWriter = 8, 20000
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := keyA
			if i%2 == 1 {
				key = keyB
			}
			c := um.Acquire(key, ip1)
			defer um.Release(c, ip1)
			for j := 0; j < perWriter; j++ {
				c.AddUp(1)
				c.AddDown(2)
			}
		}(i)
	}
	var drainedUp, drainedDown int64
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
loop:
	for {
		select {
		case <-done:
			break loop
		default:
		}
		for _, s := range um.Drain() {
			drainedUp += s.Up
			drainedDown += s.Down
		}
	}
	for _, s := range um.Drain() {
		drainedUp += s.Up
		drainedDown += s.Down
	}
	assert.Equal(t, int64(writers*perWriter), drainedUp)
	assert.Equal(t, int64(2*writers*perWriter), drainedDown)
}

func TestUserSweep(t *testing.T) {
	um, clock := newTestUserManager()
	ttl := um.IdleTTL

	a := um.Acquire(keyA, ip1)
	a.AddDown(100)
	b := um.Acquire(keyB, ip2)
	um.Release(b, ip2)

	// within the TTL nothing is deleted; the closed address is released after its window
	clock.advance(um.IPRelease + time.Second)
	um.Sweep()
	assert.Equal(t, 2, um.Len())
	s, _ := um.Get(keyB)
	assert.Empty(t, s.IPs)
	s, _ = um.Get(keyA)
	assert.Len(t, s.IPs, 1) // still connected

	// idle past the TTL: bob has no bytes to drain and goes; alice is still connected
	clock.advance(ttl)
	um.Sweep()
	_, ok := um.Get(keyB)
	assert.False(t, ok)
	_, ok = um.Get(keyA)
	assert.True(t, ok)

	// alice disconnects, but her bytes were not drained: kept until 2×TTL
	um.Release(a, ip1)
	clock.advance(ttl + time.Second)
	um.Sweep()
	_, ok = um.Get(keyA)
	assert.True(t, ok)
	clock.advance(ttl)
	um.Sweep()
	_, ok = um.Get(keyA)
	assert.False(t, ok)
	assert.Equal(t, 0, um.Len())

	// a counter deleted by the sweep is recreated by the next connection
	c := um.Acquire(keyA, ip1)
	assert.NotSame(t, a, c)
	c.AddUp(1)
	s, _ = um.Get(keyA)
	assert.Equal(t, int64(1), s.Up)
}

func TestUserSweepAfterDrain(t *testing.T) {
	um, clock := newTestUserManager()
	a := um.Acquire(keyA, ip1)
	a.AddUp(5)
	um.Release(a, ip1)
	clock.advance(um.IdleTTL + time.Second)
	um.Sweep()
	_, ok := um.Get(keyA)
	assert.True(t, ok, "undrained bytes keep the counter")
	um.Drain()
	um.Sweep()
	_, ok = um.Get(keyA)
	assert.False(t, ok)
}

func TestUserRetire(t *testing.T) {
	um, _ := newTestUserManager()
	a := um.Acquire(keyA, ip1)
	b := um.Acquire(keyB, ip1)
	a.AddUp(1)
	b.AddUp(1)
	um.Release(b, ip1)

	um.Retire(func(k UserKey) bool { return false })
	um.Sweep()
	// alice still has a connection, bob has bytes to drain
	assert.Equal(t, 2, um.Len())

	um.Drain()
	um.Sweep()
	_, ok := um.Get(keyB)
	assert.False(t, ok)
	_, ok = um.Get(keyA)
	assert.True(t, ok)

	// alice comes back in the configuration
	um.Retire(func(k UserKey) bool { return true })
	um.Release(a, ip1)
	um.Sweep()
	_, ok = um.Get(keyA)
	assert.True(t, ok, "a recent user that is configured again is kept")
}

func TestUserAcquireWhileSweeping(t *testing.T) {
	um, clock := newTestUserManager()
	um.IdleTTL = 0
	clock.advance(time.Hour)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				um.Sweep()
			}
		}
	}()
	var total int64
	for i := 0; i < 2000; i++ {
		c := um.Acquire(keyA, ip1)
		c.AddUp(1)
		total++
		// the counter is never deleted while a connection holds it
		s, ok := um.Get(keyA)
		require.True(t, ok)
		require.GreaterOrEqual(t, s.Conns, int64(1))
		for _, d := range um.Drain() {
			total -= d.Up
		}
		um.Release(c, ip1)
	}
	close(stop)
	wg.Wait()
	assert.Equal(t, int64(0), total, "every byte was drained exactly once")
}
