package inbounduser

import (
	"crypto/subtle"
	"io"

	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
)

// Snapshot is the user table of a Set at one moment.
type Snapshot[K comparable] struct {
	set *Set[K]
	t   *table[K]
}

// Snapshot returns the current table.
func (s *Set[K]) Snapshot() Snapshot[K] {
	return Snapshot[K]{set: s, t: s.cur.Load()}
}

// Lookup returns the entry of key in the snapshot.
func (sn Snapshot[K]) Lookup(key K) (*Entry, bool) {
	e, ok := sn.t.byKey[key]
	return e, ok
}

// AuthStore is an auth.AuthStore (socks, http, mixed) whose users can be
// replaced at runtime. Every connection takes an authenticator pinned to the
// table of that moment; after the handshake the handler binds the
// connection to the user it verified (auth.SessionBinder), so removing or
// re-keying the user closes it. With no users nobody is let in: unlike an
// empty `users` in the configuration, it never turns authentication off.
type AuthStore struct {
	users *Set[string]
}

func authKey(user C.InboundUser) (string, error) { return user.Name, nil }

// NewAuthStore returns a store for users (Name = username, Secret = password).
func NewAuthStore(users []C.InboundUser) *AuthStore {
	set, _ := New(authKey, users) // authKey never fails
	return &AuthStore{users: set}
}

// Authenticator implements auth.AuthStore.
func (a *AuthStore) Authenticator() auth.Authenticator {
	return &snapshotAuthenticator{a.users.Snapshot()}
}

// SetAuthenticator implements auth.AuthStore; the users are set with Replace.
func (a *AuthStore) SetAuthenticator(auth.Authenticator) {}

// Users returns the current users.
func (a *AuthStore) Users() []C.InboundUser { return a.users.Users() }

// Replace swaps the users; the sessions of the removed and changed users are
// closed.
func (a *AuthStore) Replace(users []C.InboundUser) (Change, error) {
	if err := NoFlow("socks/http", users); err != nil {
		return Change{}, err
	}
	return a.users.Replace(users)
}

type snapshotAuthenticator struct {
	sn Snapshot[string]
}

func (s *snapshotAuthenticator) Verify(user string, pass string) bool {
	e, ok := s.sn.Lookup(user)
	return ok && subtle.ConstantTimeCompare([]byte(e.Secret()), []byte(pass)) == 1
}

func (s *snapshotAuthenticator) Users() []string {
	names := make([]string, 0, len(s.sn.t.list))
	for _, e := range s.sn.t.list {
		names = append(names, e.Name())
	}
	return names
}

// Bind implements auth.SessionBinder.
func (s *snapshotAuthenticator) Bind(user string, c io.Closer) (release func(), ok bool) {
	e, found := s.sn.Lookup(user)
	if !found {
		return func() {}, false
	}
	return s.sn.set.Bind(e, c)
}

var _ auth.SessionBinder = (*snapshotAuthenticator)(nil)
