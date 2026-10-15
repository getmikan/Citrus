package auth

import (
	"io"
	"sync"

	"github.com/metacubex/mihomo/component/auth"
)

// RevocableStore is an auth.AuthStore whose authenticator is swapped as a
// whole, as the global `authentication` is on a reload, and that closes the
// sessions the swap invalidates:
//
//   - a session bound to a user that is gone or has another password;
//   - a session let in while authentication was off, once it is turned on.
//
// A session whose user kept its password survives, so a reload that leaves
// the users alone drops nothing. Turning authentication off closes nothing.
type RevocableStore struct {
	mu       sync.Mutex
	cur      auth.Authenticator
	sessions map[*revocableSession]struct{}
}

type revocableSession struct {
	closer io.Closer
	user   string
	// verified is the authenticator the user was verified by; nil for a
	// session let in without authentication
	verified auth.Authenticator
}

// NewRevocableStore returns a store that starts with authenticator (nil: off).
func NewRevocableStore(authenticator auth.Authenticator) *RevocableStore {
	return &RevocableStore{cur: authenticator, sessions: make(map[*revocableSession]struct{})}
}

// Authenticator implements auth.AuthStore. The result is pinned to the
// current users; it binds sessions with auth.BindSession.
func (s *RevocableStore) Authenticator() auth.Authenticator {
	s.mu.Lock()
	cur := s.cur
	s.mu.Unlock()
	if cur == nil {
		return nil
	}
	return &revocableAuthenticator{store: s, inner: cur}
}

// SetAuthenticator implements auth.AuthStore. The invalidated sessions are
// closed before it returns.
func (s *RevocableStore) SetAuthenticator(authenticator auth.Authenticator) {
	if ra, ok := authenticator.(*revocableAuthenticator); ok {
		authenticator = ra.inner
	}
	var closers []io.Closer
	s.mu.Lock()
	s.cur = authenticator
	if authenticator != nil {
		for ss := range s.sessions {
			if ss.verified != nil && auth.SameCredentials(ss.verified, authenticator, ss.user) {
				ss.verified = authenticator
				continue
			}
			closers = append(closers, ss.closer)
			delete(s.sessions, ss)
		}
	}
	s.mu.Unlock()
	for _, c := range closers {
		_ = c.Close()
	}
}

// bind registers a session verified by verified (nil: let in without
// authentication). ok is false when the store changed in a way that
// invalidates it since the handshake took the authenticator.
func (s *RevocableStore) bind(verified auth.Authenticator, user string, c io.Closer) (release func(), ok bool) {
	s.mu.Lock()
	if verified == nil {
		if s.cur != nil {
			s.mu.Unlock()
			return func() {}, false
		}
	} else if !auth.SameCredentials(verified, s.cur, user) {
		s.mu.Unlock()
		return func() {}, false
	} else {
		verified = s.cur
	}
	ss := &revocableSession{closer: c, user: user, verified: verified}
	s.sessions[ss] = struct{}{}
	s.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.sessions, ss)
			s.mu.Unlock()
		})
	}, true
}

type revocableAuthenticator struct {
	store *RevocableStore
	inner auth.Authenticator
}

func (a *revocableAuthenticator) Verify(user string, pass string) bool {
	return a.inner.Verify(user, pass)
}

func (a *revocableAuthenticator) Users() []string { return a.inner.Users() }

// Bind implements auth.SessionBinder.
func (a *revocableAuthenticator) Bind(user string, c io.Closer) (release func(), ok bool) {
	return a.store.bind(a.inner, user, c)
}

var _ auth.SessionBinder = (*revocableAuthenticator)(nil)

// BindSession ties an accepted session to the store it was checked against:
// to the verified user when authenticator (taken from store) is not nil, as
// auth.BindSession does; otherwise, for a RevocableStore, to the state
// "authentication off", so that turning it on closes the session. ok false
// means the session must be dropped.
func BindSession(store auth.AuthStore, authenticator auth.Authenticator, user string, c io.Closer) (release func(), ok bool) {
	if authenticator != nil {
		return auth.BindSession(authenticator, user, c)
	}
	if rs, isRevocable := store.(*RevocableStore); isRevocable {
		return rs.bind(nil, "", c)
	}
	return func() {}, true
}
