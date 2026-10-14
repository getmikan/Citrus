package inbound

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/metacubex/mihomo/component/auth"
	"github.com/metacubex/mihomo/component/eventbus"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	"github.com/metacubex/mihomo/listener/inbounduser"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// Runtime user management (constant.InboundUserUpdater).
//
// The protocol listeners keep their users in an inbounduser.Set and expose
// Users and ReplaceUsers; the wrappers here add what is common to every
// protocol: the users of a listener that does not listen yet come from its
// configuration, and after a change the tunnel connections of the removed and
// re-keyed users are closed and the traffic counters of the removed users are
// retired (those of the added ones are kept again).

// userReplacer is implemented by the protocol listeners whose users can be
// replaced in place.
type userReplacer interface {
	Users() []C.InboundUser
	ReplaceUsers(users []C.InboundUser) (inbounduser.Change, error)
}

// listenerUsers returns the users of l when it listens, the users of the
// configuration otherwise.
func listenerUsers(l any, configUsers func() []C.InboundUser) []C.InboundUser {
	if r, ok := l.(userReplacer); ok && !isNil(r) {
		return r.Users()
	}
	return configUsers()
}

func isNil(v any) bool {
	rv := reflect.ValueOf(v)
	return v == nil || (rv.Kind() == reflect.Pointer && rv.IsNil())
}

// setListenerUsers replaces the users of the listener l of the inbound name.
func setListenerUsers(name string, l any, users []C.InboundUser) error {
	r, ok := l.(userReplacer)
	if !ok || isNil(r) {
		return fmt.Errorf("%w: inbound %q is not listening", C.ErrInboundUsersUnsupported, name)
	}
	change, err := r.ReplaceUsers(users)
	if err != nil {
		return err
	}
	settleUserChange(name, change)
	return nil
}

// settleUserChange closes what is left of the removed and re-keyed users
// (the protocol already closed their sessions; this catches the tunnel
// connections, e.g. UDP NAT sessions), retires or revives their traffic
// counters and reports the change on the event stream.
func settleUserChange(name string, change inbounduser.Change) {
	if revoked := change.Revoked(); len(revoked) > 0 {
		statistic.DefaultManager.CloseUserConnections(name, revoked...)
	}
	users := statistic.DefaultManager.Users()
	users.SetRetired(name, change.Removed, true)
	users.SetRetired(name, change.Added, false)
	if (len(change.Added) > 0 || len(change.Removed) > 0 || len(change.Changed) > 0) && eventbus.Enabled(eventbus.TypeUserChanged) {
		eventbus.Publish(eventbus.TypeUserChanged, eventbus.UserChanged{Inbound: name, Added: change.Added, Removed: change.Removed, Changed: change.Changed})
	}
}

// userNames returns the names of users, without the empty ones.
func userNames(users []C.InboundUser) []string {
	names := make([]string, 0, len(users))
	for _, user := range users {
		if user.Name != "" {
			names = append(names, user.Name)
		}
	}
	return names
}

// equalExceptUsers reports whether two option structs (or pointers to them)
// of the same type are equal once their Users fields are cleared.
func equalExceptUsers(a, b any) bool {
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	for va.Kind() == reflect.Pointer || va.Kind() == reflect.Interface {
		if va.IsNil() {
			return false
		}
		va = va.Elem()
	}
	for vb.Kind() == reflect.Pointer || vb.Kind() == reflect.Interface {
		if vb.IsNil() {
			return false
		}
		vb = vb.Elem()
	}
	if va.Type() != vb.Type() || va.Kind() != reflect.Struct {
		return false
	}
	ca, cb := withoutUsers(va), withoutUsers(vb)
	if !ca.IsValid() || !cb.IsValid() {
		return false
	}
	ja, errA := json.Marshal(ca.Interface())
	jb, errB := json.Marshal(cb.Interface())
	return errA == nil && errB == nil && string(ja) == string(jb)
}

func withoutUsers(v reflect.Value) reflect.Value {
	c := reflect.New(v.Type()).Elem()
	c.Set(v)
	f := c.FieldByName("Users")
	if !f.IsValid() || !f.CanSet() {
		return reflect.Value{}
	}
	f.Set(reflect.Zero(f.Type()))
	return c
}

// mapUsers converts a name -> secret map of a configuration.
func mapUsers(m map[string]string) []C.InboundUser { return inbounduser.FromMap(m) }

// authUsers converts the users of socks, http, mixed and trusttunnel.
func authUsers(a AuthUsers) []C.InboundUser {
	users := make([]C.InboundUser, len(a))
	for i, user := range a {
		users[i] = C.InboundUser{Name: user.Username, Secret: user.Password}
	}
	return users
}

// authStoreUsers backs the socks, http and mixed inbounds. With users in
// the configuration they authenticate against a store whose users can be
// replaced at runtime; without users (the global authentication, or `users:
// []` to turn it off) there is nothing to replace.
type authStoreUsers struct {
	name  string
	users AuthUsers
	store *inbounduser.AuthStore // nil without users
}

// newAuthStoreUsers rejects a user with an empty username: the empty name
// means "no user" to IN-USER, the user limits and the session binding, so
// such an account could not be limited or revoked.
func newAuthStoreUsers(name string, users AuthUsers) (authStoreUsers, error) {
	for i, user := range users {
		if user.Username == "" {
			return authStoreUsers{}, fmt.Errorf("%w: users[%d]: empty username", C.ErrInvalidInboundUser, i)
		}
	}
	a := authStoreUsers{name: name, users: users}
	if len(users) > 0 {
		a.store = inbounduser.NewAuthStore(authUsers(users))
	}
	return a, nil
}

func (a *authStoreUsers) authStore() auth.AuthStore {
	if a.store != nil {
		return a.store
	}
	return a.users.GetAuthStore()
}

// Users implements constant.InboundUserUpdater
func (a *authStoreUsers) Users() []C.InboundUser {
	if a.store != nil {
		return a.store.Users()
	}
	return authUsers(a.users)
}

// SetUsers implements constant.InboundUserUpdater
func (a *authStoreUsers) SetUsers(users []C.InboundUser) error {
	if a.store == nil {
		return fmt.Errorf("%w: inbound %q has no users of its own (it uses the global authentication or none); set users in its configuration", C.ErrInboundUsersUnsupported, a.name)
	}
	change, err := a.store.Replace(users)
	if err != nil {
		return err
	}
	settleUserChange(a.name, change)
	return nil
}

// InboundUsers implements constant.InboundUserLister
func (a *authStoreUsers) InboundUsers() []string {
	if a.store == nil && a.users == nil { // the global authentication
		if authenticator := authStore.Default.Authenticator(); authenticator != nil {
			return authenticator.Users()
		}
		return nil
	}
	return userNames(a.Users())
}
