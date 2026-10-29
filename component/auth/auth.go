package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"io"
)

type Authenticator interface {
	Verify(user string, pass string) bool
	Users() []string
}

type AuthStore interface {
	Authenticator() Authenticator
	SetAuthenticator(Authenticator)
}

// SessionBinder is implemented by the authenticators whose users can be
// removed or re-keyed at runtime. After a successful Verify the handler binds
// the session (the client connection) to the user: removing or re-keying the
// user closes it. ok is false when the user is already gone; the handler must
// drop the session. release is called when the session ends.
type SessionBinder interface {
	Bind(user string, c io.Closer) (release func(), ok bool)
}

// BindSession binds c to user when authenticator is a SessionBinder; it
// always succeeds with the other authenticators.
func BindSession(authenticator Authenticator, user string, c io.Closer) (release func(), ok bool) {
	if binder, isBinder := authenticator.(SessionBinder); isBinder {
		return binder.Bind(user, c)
	}
	return func() {}, true
}

type AuthUser struct {
	User string
	Pass string
}

// The passwords are kept as SHA-256 digests so that Verify compares
// fixed-length values in constant time, also for unknown users.
type inMemoryAuthenticator struct {
	storage   map[string][sha256.Size]byte
	usernames []string
}

func (au *inMemoryAuthenticator) Verify(user string, pass string) bool {
	realPass, ok := au.storage[user] // the zero digest for an unknown user
	digest := sha256.Sum256([]byte(pass))
	return subtle.ConstantTimeCompare(realPass[:], digest[:]) == 1 && ok
}

func (au *inMemoryAuthenticator) Users() []string { return au.usernames }

// SameCredentials reports whether user has the same password in a and b, so
// that a session verified by a stays valid under b. It is false when either
// lacks the user, and for authenticators whose credentials it cannot compare
// unless a and b are the same.
func SameCredentials(a, b Authenticator, user string) bool {
	if a == nil || b == nil {
		return false
	}
	if a == b {
		return true
	}
	am, ok1 := a.(*inMemoryAuthenticator)
	bm, ok2 := b.(*inMemoryAuthenticator)
	if !ok1 || !ok2 {
		return false
	}
	pa, ok1 := am.storage[user]
	pb, ok2 := bm.storage[user]
	return ok1 && ok2 && pa == pb
}

func NewAuthenticator(users []AuthUser) Authenticator {
	if len(users) == 0 {
		return nil
	}
	au := &inMemoryAuthenticator{
		storage:   make(map[string][sha256.Size]byte),
		usernames: make([]string, 0, len(users)),
	}
	for _, user := range users {
		au.storage[user.User] = sha256.Sum256([]byte(user.Pass))
		au.usernames = append(au.usernames, user.User)
	}
	return au
}

var AlwaysValid Authenticator = alwaysValid{}

type alwaysValid struct{}

func (alwaysValid) Verify(string, string) bool { return true }

func (alwaysValid) Users() []string { return nil }
