package auth

import (
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/component/auth"

	"github.com/stretchr/testify/require"
)

type closer struct{ closed atomic.Bool }

func (c *closer) Close() error {
	c.closed.Store(true)
	return nil
}

func users(pairs ...string) auth.Authenticator {
	var list []auth.AuthUser
	for i := 0; i+1 < len(pairs); i += 2 {
		list = append(list, auth.AuthUser{User: pairs[i], Pass: pairs[i+1]})
	}
	return auth.NewAuthenticator(list)
}

func bindVerified(t *testing.T, store auth.AuthStore, user, pass string) (*closer, func()) {
	t.Helper()
	a := store.Authenticator()
	require.NotNil(t, a)
	require.True(t, a.Verify(user, pass))
	c := &closer{}
	release, ok := BindSession(store, a, user, c)
	require.True(t, ok)
	return c, release
}

func TestRevocableStoreReload(t *testing.T) {
	store := NewRevocableStore(users("alice", "a", "bob", "b", "carol", "c"))
	alice, _ := bindVerified(t, store, "alice", "a")
	bob, _ := bindVerified(t, store, "bob", "b")
	carol, releaseCarol := bindVerified(t, store, "carol", "c")
	releaseCarol() // ended before the reload

	// the same users in a new authenticator: nothing is closed
	store.SetAuthenticator(users("alice", "a", "bob", "b", "carol", "c"))
	require.False(t, alice.closed.Load())
	require.False(t, bob.closed.Load())

	// bob re-keyed, carol removed
	store.SetAuthenticator(users("alice", "a", "bob", "b2"))
	require.False(t, alice.closed.Load())
	require.True(t, bob.closed.Load())
	require.False(t, carol.closed.Load(), "a released session is not closed")

	// turning authentication off closes nothing; on again with alice gone
	store.SetAuthenticator(nil)
	require.False(t, alice.closed.Load())
	store.SetAuthenticator(users("bob", "b2"))
	require.True(t, alice.closed.Load())
}

func TestRevocableStoreTurnedOn(t *testing.T) {
	store := NewRevocableStore(nil)
	require.Nil(t, store.Authenticator())
	open := &closer{}
	_, ok := BindSession(store, nil, "", open)
	require.True(t, ok)

	store.SetAuthenticator(users("alice", "a"))
	require.True(t, open.closed.Load(), "a session let in without authentication survived turning it on")

	// a handshake that started while authentication was off is refused
	late := &closer{}
	_, ok = BindSession(store, nil, "", late)
	require.False(t, ok)
}

func TestRevocableStoreStaleHandshake(t *testing.T) {
	store := NewRevocableStore(users("alice", "a"))
	a := store.Authenticator()
	require.True(t, a.Verify("alice", "a"))
	store.SetAuthenticator(users("alice", "a2")) // re-keyed while the handshake ran

	_, ok := BindSession(store, a, "alice", &closer{})
	require.False(t, ok)

	// with an unchanged password a stale snapshot still binds
	b := store.Authenticator()
	store.SetAuthenticator(users("alice", "a2", "bob", "b"))
	c := &closer{}
	_, ok = BindSession(store, b, "alice", c)
	require.True(t, ok)
	store.SetAuthenticator(users("bob", "b"))
	require.True(t, c.closed.Load())
}

func TestDefaultStoreIsRevocable(t *testing.T) {
	_, ok := Default.(*RevocableStore)
	require.True(t, ok)
}
