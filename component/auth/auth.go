package auth

import "io"

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

type inMemoryAuthenticator struct {
	storage   map[string]string
	usernames []string
}

func (au *inMemoryAuthenticator) Verify(user string, pass string) bool {
	realPass, ok := au.storage[user]
	return ok && realPass == pass
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
		storage:   make(map[string]string),
		usernames: make([]string, 0, len(users)),
	}
	for _, user := range users {
		au.storage[user.User] = user.Pass
		au.usernames = append(au.usernames, user.User)
	}
	return au
}

var AlwaysValid Authenticator = alwaysValid{}

type alwaysValid struct{}

func (alwaysValid) Verify(string, string) bool { return true }

func (alwaysValid) Users() []string { return nil }
