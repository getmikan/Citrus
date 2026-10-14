package eventbus

import (
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/authevent"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func recv(t *testing.T, s *Subscription) Event {
	t.Helper()
	select {
	case e, ok := <-s.C():
		require.True(t, ok, "channel closed")
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
		return Event{}
	}
}

func noEvent(t *testing.T, s *Subscription) {
	t.Helper()
	select {
	case e := <-s.C():
		t.Fatalf("unexpected event %+v", e)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestParseTypes(t *testing.T) {
	m, err := ParseTypes("")
	require.NoError(t, err)
	assert.Equal(t, All, m)
	m, err = ParseTypes("auth, user.limit")
	require.NoError(t, err)
	assert.Equal(t, bit(TypeAuth)|bit(TypeUserLimit), m)
	_, err = ParseTypes("auth,nope")
	assert.ErrorContains(t, err, "nope")
	_, err = ParseTypes(TypeDropped)
	assert.Error(t, err, "dropped is not a filter")
}

func TestFanOutAndFilter(t *testing.T) {
	b := New()
	assert.False(t, b.Enabled(TypeAuth))
	b.Publish(TypeAuth, "nobody listens") // no-op

	all := b.Subscribe(All, 8)
	auth := b.Subscribe(bit(TypeAuth), 8)
	limits := b.Subscribe(bit(TypeUserLimit), 8)
	assert.True(t, b.Enabled(TypeAuth))
	assert.True(t, b.Enabled(TypeUserLimit))
	assert.False(t, b.Enabled("unknown"))

	b.Publish(TypeAuth, 1)
	b.Publish(TypeUserLimit, 2)
	b.Publish(TypeConfigReload, 3)

	assert.Equal(t, 1, recv(t, all).Data)
	assert.Equal(t, 2, recv(t, all).Data)
	e := recv(t, all)
	assert.Equal(t, TypeConfigReload, e.Type)
	assert.False(t, e.Time.IsZero())
	assert.Equal(t, 1, recv(t, auth).Data)
	noEvent(t, auth)
	assert.Equal(t, 2, recv(t, limits).Data)
	noEvent(t, limits)

	assert.Equal(t, uint64(1), b.Published()[0])
	all.Close()
	auth.Close()
	limits.Close()
	assert.False(t, b.Enabled(TypeAuth))
	assert.Equal(t, 0, b.Subscribers())
}

func TestSlowSubscriberDrops(t *testing.T) {
	b := New()
	slow := b.Subscribe(All, 2)
	fast := b.Subscribe(All, 100)
	defer slow.Close()
	defer fast.Close()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			b.Publish(TypeAuth, i)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a full subscriber")
	}
	for i := 0; i < 10; i++ {
		assert.Equal(t, i, recv(t, fast).Data)
	}
	assert.Equal(t, 0, recv(t, slow).Data)
	assert.Equal(t, 1, recv(t, slow).Data)
	noEvent(t, slow)
	assert.Equal(t, uint64(8), slow.TakeDropped())
	assert.Equal(t, uint64(0), slow.TakeDropped(), "taken")
	assert.Equal(t, uint64(0), fast.TakeDropped())
	assert.Equal(t, uint64(8), b.Dropped())
}

func TestUnsubscribe(t *testing.T) {
	b := New()
	before := runtime.NumGoroutine()
	for i := 0; i < 100; i++ {
		s := b.Subscribe(bit(TypeAuth), 4)
		b.Publish(TypeAuth, i)
		s.Close()
		s.Close() // idempotent
		_, ok := <-s.C()
		assert.True(t, ok, "buffered event still readable")
		_, ok = <-s.C()
		assert.False(t, ok, "closed")
	}
	b.Publish(TypeAuth, "after") // no subscriber, no panic on a closed channel
	assert.Equal(t, 0, b.Subscribers())
	assert.False(t, b.Enabled(TypeAuth))
	assert.LessOrEqual(t, runtime.NumGoroutine(), before, "the bus starts no goroutines")

	// closing while publishing concurrently
	s := b.Subscribe(All, 1)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				b.Publish(TypeAuth, 0)
			}
		}
	}()
	time.Sleep(5 * time.Millisecond)
	s.Close()
	close(stop)
}

// resetAuth forgets the clients of the current window, so that a test (or a
// repeated run with -count) starts from an empty one.
func resetAuth() {
	a := defaultAuth
	a.mu.Lock()
	if a.timer != nil {
		a.timer.Stop()
	}
	a.pending, a.overflow, a.timer = nil, nil, nil
	a.mu.Unlock()
}

func withAuthWindow(t *testing.T, d time.Duration, keys int) {
	resetAuth()
	oldW, oldK := AuthWindow, AuthMaxKeys
	AuthWindow, AuthMaxKeys = d, keys
	t.Cleanup(func() {
		resetAuth()
		AuthWindow, AuthMaxKeys = oldW, oldK
	})
}

func TestAuthFailureFromAuthevent(t *testing.T) {
	withAuthWindow(t, 100*time.Millisecond, 2)
	assert.False(t, authevent.Enabled(), "nobody subscribed: the protocols skip the event")

	s := Subscribe(bit(TypeAuth), 64)
	defer s.Close()
	require.True(t, authevent.Enabled())

	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	remote := func(ip byte, port int) net.Addr { return &net.TCPAddr{IP: net.IPv4(192, 0, 2, ip), Port: port} }
	// a scanner: many attempts from one address, other ports
	for i := 0; i < 50; i++ {
		authevent.EmitAddr("vless", authevent.ReasonWrongCredentials, local, remote(1, 40000+i))
	}
	// two more clients; the cap is two, so the third is an overflow
	authevent.EmitAddr("trojan", authevent.ReasonWrongCredentials, local, remote(2, 1))
	authevent.EmitAddr("trojan", authevent.ReasonWrongCredentials, local, remote(3, 1))

	first := recv(t, s).Data.(Auth)
	assert.Equal(t, Auth{Result: AuthFailure, Protocol: "vless", Local: "127.0.0.1:443", Remote: "192.0.2.1", Reason: authevent.ReasonWrongCredentials, Count: 1}, first)
	second := recv(t, s).Data.(Auth)
	assert.Equal(t, "192.0.2.2", second.Remote)

	// the window ends: the repetitions in one event, the overflow in another
	got := map[bool]Auth{}
	for i := 0; i < 2; i++ {
		a := recv(t, s).Data.(Auth)
		got[a.Overflow] = a
	}
	assert.Equal(t, Auth{Result: AuthFailure, Protocol: "vless", Local: "127.0.0.1:443", Remote: "192.0.2.1", Reason: authevent.ReasonWrongCredentials, Count: 49, Repeated: true}, got[false])
	assert.Equal(t, Auth{Result: AuthFailure, Count: 1, Overflow: true}, got[true])
	noEvent(t, s)

	// a new window reports the client at once again
	authevent.EmitAddr("vless", authevent.ReasonWrongCredentials, local, remote(1, 1))
	assert.Equal(t, int64(1), recv(t, s).Data.(Auth).Count)
}

func TestAuthSuccess(t *testing.T) {
	withAuthWindow(t, 50*time.Millisecond, 16)
	PublishAuthSuccess("in", "alice", netip.MustParseAddr("192.0.2.7")) // nobody listens
	s := Subscribe(bit(TypeAuth), 8)
	defer s.Close()
	PublishAuthSuccess("in", "alice", netip.MustParseAddr("192.0.2.7"))
	assert.Equal(t, Auth{Result: AuthSuccess, Inbound: "in", User: "alice", Remote: "192.0.2.7", Count: 1}, recv(t, s).Data)
}
