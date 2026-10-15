package inbounduser

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func secretKey(user C.InboundUser) (string, error) { return user.Secret, nil }

type closer struct{ closed atomic.Int32 }

func (c *closer) Close() error { c.closed.Add(1); return nil }

func TestReplaceKeepsUnchangedEntries(t *testing.T) {
	s, err := New(secretKey, []C.InboundUser{{Name: "a", Secret: "1"}, {Name: "b", Secret: "2"}, {Name: "c", Secret: "3"}})
	require.NoError(t, err)
	ea, _ := s.Lookup("1")
	eb, _ := s.Lookup("2")
	ec, _ := s.Lookup("3")
	ca, cb, cc := &closer{}, &closer{}, &closer{}
	_, ok := s.Bind(ea, ca)
	require.True(t, ok)
	_, ok = s.Bind(eb, cb)
	require.True(t, ok)
	_, ok = s.Bind(ec, cc)
	require.True(t, ok)

	// a unchanged, b re-keyed, c removed, d added
	change, err := s.Replace([]C.InboundUser{{Name: "a", Secret: "1"}, {Name: "b", Secret: "22"}, {Name: "d", Secret: "4"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"d"}, change.Added)
	assert.Equal(t, []string{"b"}, change.Changed)
	assert.Equal(t, []string{"c"}, change.Removed)
	assert.ElementsMatch(t, []string{"b", "c"}, change.Revoked())

	assert.Zero(t, ca.closed.Load(), "the session of an unchanged user stays")
	assert.Equal(t, int32(1), cb.closed.Load(), "the session of a re-keyed user is closed")
	assert.Equal(t, int32(1), cc.closed.Load(), "the session of a removed user is closed")
	assert.False(t, ea.Revoked())
	assert.True(t, eb.Revoked())
	assert.True(t, ec.Revoked())

	got, ok := s.Lookup("1")
	assert.True(t, ok)
	assert.Same(t, ea, got, "an unchanged user keeps its entry")
	_, ok = s.Lookup("2")
	assert.False(t, ok, "the old secret is gone")
	_, ok = s.Lookup("22")
	assert.True(t, ok)

	// a handshake that looked up a revoked entry cannot bind
	late := &closer{}
	_, ok = s.Bind(eb, late)
	assert.False(t, ok)
	assert.Zero(t, late.closed.Load(), "the caller drops the session itself")

	// a released session is not closed by a later revocation
	release, ok := s.Bind(ea, &closer{})
	require.True(t, ok)
	release()
	release()
}

func TestReplaceValidation(t *testing.T) {
	s, err := New(secretKey, []C.InboundUser{{Name: "a", Secret: "1"}})
	require.NoError(t, err)
	keyErr := func(user C.InboundUser) (string, error) {
		if user.Secret == "bad" {
			return "", errors.New("bad secret")
		}
		return user.Secret, nil
	}
	sk, err := New(keyErr, nil)
	require.NoError(t, err)
	for _, tc := range []struct {
		set   *Set[string]
		users []C.InboundUser
	}{
		{s, []C.InboundUser{{Name: "", Secret: "1"}}},
		{s, []C.InboundUser{{Name: "a", Secret: ""}}},
		{s, []C.InboundUser{{Name: "a", Secret: "1"}, {Name: "a", Secret: "2"}}},
		{s, []C.InboundUser{{Name: "a", Secret: "1"}, {Name: "b", Secret: "1"}}},
		{sk, []C.InboundUser{{Name: "a", Secret: "bad"}}},
	} {
		_, err := tc.set.Replace(tc.users)
		assert.ErrorIs(t, err, C.ErrInvalidInboundUser, "%v", tc.users)
	}
	assert.Equal(t, []C.InboundUser{{Name: "a", Secret: "1"}}, s.Users(), "a failed replace changes nothing")
}

func TestNewIsLenient(t *testing.T) {
	// the configuration always allowed unnamed users and a repeated key
	s, err := New(secretKey, []C.InboundUser{{Secret: "1"}, {Name: "b", Secret: "2"}, {Name: "c", Secret: "2"}})
	require.NoError(t, err)
	assert.Equal(t, 2, s.Len())
	e, _ := s.Lookup("2")
	assert.Equal(t, "c", e.Name(), "the last user of a repeated key wins")
	assert.Len(t, s.Entries(), 1, "unnamed entries are not listed by name")
}

// TestBindRace replaces the users while handshakes bind sessions: in the
// end every session bound to a revoked entry has been closed (by the
// revocation), and Bind refused the others.
func TestBindRace(t *testing.T) {
	s, err := New(secretKey, []C.InboundUser{{Name: "a", Secret: "1"}})
	require.NoError(t, err)
	type bound struct {
		e *Entry
		c *closer
	}
	var mu sync.Mutex
	var sessions []bound
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				e, ok := s.Lookup("1")
				if !ok {
					continue
				}
				c := &closer{}
				if _, ok := s.Bind(e, c); ok {
					mu.Lock()
					sessions = append(sessions, bound{e, c})
					mu.Unlock()
				}
			}
		}()
	}
	// Let the binders get going before the swaps start: on a slow or
	// loaded machine the loop below can otherwise finish before any bind.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(sessions) > 0
	}, 5*time.Second, time.Millisecond)
	for i := 0; i < 2000; i++ {
		users := []C.InboundUser{{Name: "a", Secret: "1"}}
		if i%2 == 0 {
			users = []C.InboundUser{{Name: "b", Secret: "2"}}
		}
		_, err := s.Replace(users)
		require.NoError(t, err)
	}
	close(stop)
	wg.Wait()
	require.NotEmpty(t, sessions)
	for _, b := range sessions {
		if b.e.Revoked() {
			assert.Equal(t, int32(1), b.c.closed.Load(), "a session of a revoked entry is closed once")
		} else {
			assert.Zero(t, b.c.closed.Load())
		}
	}
}
