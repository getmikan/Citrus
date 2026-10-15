package listener

import (
	"errors"
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
)

// Runtime user management of the `listeners:` inbounds, for the controller
// and for embedders.
//
// The changes live in memory only: the configuration stays the source of
// truth, and the next configuration reload sets the users of the
// configuration again (in place when nothing else of the listener changed).
// An embedder that manages users at runtime keeps its own list and writes it
// into the configuration it applies.

var (
	// ErrInboundNotFound is returned for a name that is not a listener.
	ErrInboundNotFound = errors.New("inbound not found")
	// ErrInboundUserNotFound is returned for a user the inbound does not have.
	ErrInboundUserNotFound = errors.New("inbound user not found")
	// ErrInboundUserExists is returned when adding a name the inbound has.
	ErrInboundUserExists = errors.New("inbound user already exists")
)

// inboundUpdater returns the listener name and its user updater; the
// caller holds inboundMux.
func inboundUpdater(name string) (C.InboundListener, C.InboundUserUpdater, error) {
	l, ok := inboundListeners[name]
	if !ok {
		return nil, nil, fmt.Errorf("%w: %q", ErrInboundNotFound, name)
	}
	updater, ok := l.(C.InboundUserUpdater)
	if !ok {
		return l, nil, fmt.Errorf("%w: inbound %q", C.ErrInboundUsersUnsupported, name)
	}
	return l, updater, nil
}

// GetInbound returns the running listener name of the `listeners:` section.
func GetInbound(name string) (C.InboundListener, bool) {
	inboundMux.Lock()
	defer inboundMux.Unlock()
	l, ok := inboundListeners[name]
	return l, ok
}

// InboundType returns the type of the listener name ("vless", "trojan"...)
// as written in the configuration, or "" when there is none.
func InboundType(name string) string {
	inboundMux.Lock()
	defer inboundMux.Unlock()
	if l, ok := inboundListeners[name]; ok {
		return inboundTypeOf(l)
	}
	return ""
}

func inboundTypeOf(l C.InboundListener) string {
	t := fmt.Sprintf("%T", l) // *inbound.Vless
	return strings.ToLower(t[strings.LastIndexByte(t, '.')+1:])
}

// InboundUsers returns the current users of the listener name, with their
// secrets.
func InboundUsers(name string) ([]C.InboundUser, error) {
	inboundMux.Lock()
	defer inboundMux.Unlock()
	_, updater, err := inboundUpdater(name)
	if err != nil {
		return nil, err
	}
	return updater.Users(), nil
}

// SetInboundUsers replaces all the users of the listener name without
// recreating it. The established connections of the users that are removed
// or whose secret changes are closed; the others are untouched.
func SetInboundUsers(name string, users []C.InboundUser) error {
	inboundMux.Lock()
	defer inboundMux.Unlock()
	_, updater, err := inboundUpdater(name)
	if err != nil {
		return err
	}
	return setUsers(name, updater, users)
}

func setUsers(name string, updater C.InboundUserUpdater, users []C.InboundUser) error {
	if err := updater.SetUsers(users); err != nil {
		return err
	}
	runtimeUsers[name] = struct{}{}
	return nil
}

// AddInboundUser adds a user to the listener name.
func AddInboundUser(name string, user C.InboundUser) error {
	return modifyInboundUsers(name, func(users []C.InboundUser) ([]C.InboundUser, error) {
		for _, u := range users {
			if u.Name == user.Name && user.Name != "" {
				return nil, fmt.Errorf("%w: %q", ErrInboundUserExists, user.Name)
			}
		}
		return append(users, user), nil
	})
}

// RemoveInboundUser removes the user of the listener name and closes its
// connections.
func RemoveInboundUser(name, user string) error {
	return modifyInboundUsers(name, func(users []C.InboundUser) ([]C.InboundUser, error) {
		for i, u := range users {
			if u.Name == user {
				return append(users[:i:i], users[i+1:]...), nil
			}
		}
		return nil, fmt.Errorf("%w: %q", ErrInboundUserNotFound, user)
	})
}

// UpdateInboundUser replaces the record (secret, flow) of the user
// user.Name of the listener name. When it changes, the connections of the
// user are closed: they authenticated with the previous secret.
func UpdateInboundUser(name string, user C.InboundUser) error {
	return modifyInboundUsers(name, func(users []C.InboundUser) ([]C.InboundUser, error) {
		for i, u := range users {
			if u.Name == user.Name {
				updated := append([]C.InboundUser(nil), users...)
				updated[i] = user
				return updated, nil
			}
		}
		return nil, fmt.Errorf("%w: %q", ErrInboundUserNotFound, user.Name)
	})
}

// ModifyInboundUser applies fn to the record of the user of the listener
// name, atomically with respect to the other changes.
func ModifyInboundUser(name, user string, fn func(*C.InboundUser) error) error {
	return modifyInboundUsers(name, func(users []C.InboundUser) ([]C.InboundUser, error) {
		for i, u := range users {
			if u.Name == user {
				updated := append([]C.InboundUser(nil), users...)
				if err := fn(&updated[i]); err != nil {
					return nil, err
				}
				if updated[i].Name != user {
					return nil, fmt.Errorf("%w: the name cannot change", C.ErrInvalidInboundUser)
				}
				return updated, nil
			}
		}
		return nil, fmt.Errorf("%w: %q", ErrInboundUserNotFound, user)
	})
}

func modifyInboundUsers(name string, fn func([]C.InboundUser) ([]C.InboundUser, error)) error {
	inboundMux.Lock()
	defer inboundMux.Unlock()
	_, updater, err := inboundUpdater(name)
	if err != nil {
		return err
	}
	users, err := fn(updater.Users())
	if err != nil {
		return err
	}
	return setUsers(name, updater, users)
}

// sameUsers reports whether a and b hold the same users, in any order.
func sameUsers(a, b []C.InboundUser) bool {
	if len(a) != len(b) {
		return false
	}
	count := make(map[C.InboundUser]int, len(a))
	for _, u := range a {
		count[u]++
	}
	for _, u := range b {
		if count[u] == 0 {
			return false
		}
		count[u]--
	}
	return true
}
