// Package inbounduser keeps the users of an inbound listener in a form that
// the handshakes read without locks and that can be replaced while the
// listener runs.
//
// A Set holds an immutable table of entries behind an atomic pointer: a
// handshake loads the table once, looks its credential up and gets the
// *Entry of the user. Replace builds a new table (copy-on-write) and swaps it
// in. A user whose record (name, secret, flow) is unchanged keeps its Entry,
// so its sessions are untouched; the entries of the users that were removed or
// changed are revoked, which closes the sessions bound to them.
//
// A protocol binds an authenticated session (the client connection, or the
// QUIC connection) to its entry with Bind. Bind and the revocation are
// serialized by the set's lock and Replace swaps the table under the same
// lock, so a handshake that authenticated against the old table either binds
// before the revocation (and is closed by it) or sees its entry revoked (and
// must drop the session): no session of a removed or re-keyed user survives.
package inbounduser

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
)

// Entry is a user of a Set as the handshakes see it.
type Entry struct {
	user     C.InboundUser
	revoked  atomic.Bool
	sessions map[*session]struct{} // guarded by the set's lock
}

// User returns the user record.
func (e *Entry) User() C.InboundUser { return e.user }

// Name returns the user name, as it goes to Metadata.InUser.
func (e *Entry) Name() string { return e.user.Name }

// Secret returns the credential.
func (e *Entry) Secret() string { return e.user.Secret }

// Flow returns the optional protocol detail (the VLESS flow).
func (e *Entry) Flow() string { return e.user.Flow }

// Revoked reports whether the user was removed or changed after the entry
// was looked up; a protocol may check it before it opens a new stream on an
// existing session.
func (e *Entry) Revoked() bool { return e.revoked.Load() }

type session struct {
	closer io.Closer
}

// KeyFunc derives the lookup key of a user (the UUID, the password hash...)
// and validates the protocol-specific fields. Its errors are reported as
// validation errors by Replace.
type KeyFunc[K comparable] func(user C.InboundUser) (K, error)

type table[K comparable] struct {
	byKey map[K]*Entry
	list  []*Entry
}

// Set is the user table of one listener.
type Set[K comparable] struct {
	mu    sync.Mutex
	cur   atomic.Pointer[table[K]]
	keyOf KeyFunc[K]
}

// Change lists the user names a Replace affected.
type Change struct {
	Added   []string // names that were not there before
	Removed []string // names that are gone
	Changed []string // names whose secret or flow changed
}

// Revoked returns the names whose sessions were closed.
func (c Change) Revoked() []string {
	return append(append([]string(nil), c.Removed...), c.Changed...)
}

// New builds a set from the users of a configuration. It is lenient the way
// the configuration always was: names may be empty or repeated, and a key
// listed twice belongs to the last user. A key error is returned as is.
func New[K comparable](keyOf KeyFunc[K], users []C.InboundUser) (*Set[K], error) {
	s := &Set[K]{keyOf: keyOf}
	t := &table[K]{byKey: make(map[K]*Entry, len(users)), list: make([]*Entry, 0, len(users))}
	for _, user := range users {
		key, err := keyOf(user)
		if err != nil {
			return nil, err
		}
		e := &Entry{user: user}
		if old, ok := t.byKey[key]; ok {
			t.list = removeEntry(t.list, old)
		}
		t.byKey[key] = e
		t.list = append(t.list, e)
	}
	s.cur.Store(t)
	return s, nil
}

// NoFlow rejects users with a flow, for the protocols that have none.
func NoFlow(protocol string, users []C.InboundUser) error {
	for _, user := range users {
		if user.Flow != "" {
			return fmt.Errorf("%w: user %q: %s has no flow", C.ErrInvalidInboundUser, user.Name, protocol)
		}
	}
	return nil
}

// FromMap converts a name -> secret map of a configuration to users, sorted
// by name.
func FromMap(m map[string]string) []C.InboundUser {
	users := make([]C.InboundUser, 0, len(m))
	for name, secret := range m {
		users = append(users, C.InboundUser{Name: name, Secret: secret})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
	return users
}

// ToMap converts users to a name -> secret map.
func ToMap(users []C.InboundUser) map[string]string {
	m := make(map[string]string, len(users))
	for _, user := range users {
		m[user.Name] = user.Secret
	}
	return m
}

func removeEntry(list []*Entry, e *Entry) []*Entry {
	for i, it := range list {
		if it == e {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// Lookup returns the entry of key. It takes no lock.
func (s *Set[K]) Lookup(key K) (*Entry, bool) {
	e, ok := s.cur.Load().byKey[key]
	return e, ok
}

// Users returns the current users in their order.
func (s *Set[K]) Users() []C.InboundUser {
	t := s.cur.Load()
	users := make([]C.InboundUser, len(t.list))
	for i, e := range t.list {
		users[i] = e.user
	}
	return users
}

// Entries returns the current entries by name (the unnamed ones are left
// out; for a repeated name the last one wins).
func (s *Set[K]) Entries() map[string]*Entry {
	t := s.cur.Load()
	entries := make(map[string]*Entry, len(t.list))
	for _, e := range t.list {
		if e.user.Name != "" {
			entries[e.user.Name] = e
		}
	}
	return entries
}

// Len returns the number of users.
func (s *Set[K]) Len() int { return len(s.cur.Load().list) }

// Validate checks users the way Replace does: every name is non-empty and
// unique, every secret is non-empty, and every key is valid and unique. The errors wrap
// C.ErrInvalidInboundUser.
// The keys are returned in the order of users.
func Validate[K comparable](keyOf KeyFunc[K], users []C.InboundUser) ([]K, error) {
	names := make(map[string]struct{}, len(users))
	seen := make(map[K]C.InboundUser, len(users))
	keys := make([]K, len(users))
	for i, user := range users {
		if user.Name == "" {
			return nil, fmt.Errorf("%w: users[%d]: empty name", C.ErrInvalidInboundUser, i)
		}
		if _, dup := names[user.Name]; dup {
			return nil, fmt.Errorf("%w: duplicate user name %q", C.ErrInvalidInboundUser, user.Name)
		}
		names[user.Name] = struct{}{}
		if user.Secret == "" {
			return nil, fmt.Errorf("%w: user %q: empty secret", C.ErrInvalidInboundUser, user.Name)
		}
		key, err := keyOf(user)
		if err != nil {
			if errors.Is(err, C.ErrInvalidInboundUser) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: user %q: %s", C.ErrInvalidInboundUser, user.Name, err)
		}
		if other, dup := seen[key]; dup {
			return nil, fmt.Errorf("%w: users %q and %q have the same secret", C.ErrInvalidInboundUser, other.Name, user.Name)
		}
		seen[key] = user
		keys[i] = key
	}
	return keys, nil
}

// Replace swaps in users after validating them (see Validate). The users
// whose record is unchanged keep their sessions; the sessions of the others
// are closed before Replace returns. On error nothing changes.
func (s *Set[K]) Replace(users []C.InboundUser) (Change, error) {
	keys, err := Validate(s.keyOf, users)
	if err != nil {
		return Change{}, err
	}

	s.mu.Lock()
	old := s.cur.Load()
	t := &table[K]{byKey: make(map[K]*Entry, len(users)), list: make([]*Entry, 0, len(users))}
	kept := make(map[*Entry]struct{}, len(users))
	for i, user := range users {
		key := keys[i]
		e, ok := old.byKey[key]
		if ok && e.user == user {
			kept[e] = struct{}{}
		} else {
			e = &Entry{user: user}
		}
		t.byKey[key] = e
		t.list = append(t.list, e)
	}
	s.cur.Store(t)

	var closers []io.Closer
	for _, e := range old.list {
		if _, ok := kept[e]; ok {
			continue
		}
		e.revoked.Store(true)
		for ss := range e.sessions {
			closers = append(closers, ss.closer)
		}
		e.sessions = nil
	}
	s.mu.Unlock()

	for _, c := range closers {
		_ = c.Close()
	}
	return diff(old.list, t.list), nil
}

func diff(old, cur []*Entry) Change {
	before := make(map[string]C.InboundUser, len(old))
	for _, e := range old {
		if e.user.Name != "" {
			before[e.user.Name] = e.user
		}
	}
	var change Change
	after := make(map[string]struct{}, len(cur))
	for _, e := range cur {
		after[e.user.Name] = struct{}{}
		prev, ok := before[e.user.Name]
		switch {
		case !ok:
			change.Added = append(change.Added, e.user.Name)
		case prev != e.user:
			change.Changed = append(change.Changed, e.user.Name)
		}
	}
	for _, e := range old {
		if _, ok := after[e.user.Name]; !ok && e.user.Name != "" {
			change.Removed = append(change.Removed, e.user.Name)
			after[e.user.Name] = struct{}{} // a name repeated in the config
		}
	}
	return change
}

// Bind ties an authenticated session to e: it is closed when e is revoked.
// When e is already revoked (the user was removed or changed while the
// handshake ran) Bind returns false and the caller must drop the session.
// release unbinds the session when it ends; it may be called more than once.
func (s *Set[K]) Bind(e *Entry, c io.Closer) (release func(), ok bool) {
	ss := &session{closer: c}
	s.mu.Lock()
	if e.revoked.Load() {
		s.mu.Unlock()
		return func() {}, false
	}
	if e.sessions == nil {
		e.sessions = make(map[*session]struct{})
	}
	e.sessions[ss] = struct{}{}
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		delete(e.sessions, ss)
		s.mu.Unlock()
	}, true
}
