package sing_shadowsocks

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"

	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/inbounduser"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/ntp"

	shadowsocks "github.com/metacubex/sing-shadowsocks"
	"github.com/metacubex/sing-shadowsocks/shadowaead_2022"
	"github.com/metacubex/sing/common/auth"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
)

// multiUserKeyLength lists the Shadowsocks 2022 methods that support
// multiple users through the extensible identity header (EIH) and their key
// length. The chacha20/chacha8 2022 methods have no EIH.
var multiUserKeyLength = map[string]int{
	"2022-blake3-aes-128-gcm": 16,
	"2022-blake3-aes-256-gcm": 32,
	"2022-blake3-aes-128-ccm": 16,
	"2022-blake3-aes-256-ccm": 32,
}

// ValidateUsers checks the multi-user part of a Shadowsocks server config:
// users are only allowed with the AES Shadowsocks 2022 methods, the server
// key (iPSK) and every user key (uPSK) must be base64 of exactly the method's
// key length, and user names and keys must be unique. No users is valid.
func ValidateUsers(cipher, password string, users []LC.ShadowsocksUser) error {
	if len(users) == 0 {
		return nil
	}
	keyLength, ok := multiUserKeyLength[cipher]
	if !ok {
		return fmt.Errorf("shadowsocks: users are only supported with 2022-blake3-aes-* methods, not %q", cipher)
	}
	if err := checkKey(password, keyLength); err != nil {
		return fmt.Errorf("shadowsocks: server password (iPSK): %w", err)
	}
	names := make(map[string]struct{}, len(users))
	keys := make(map[string]string, len(users)+1)
	keys[password] = ""
	for i, user := range users {
		if user.Name == "" {
			return fmt.Errorf("shadowsocks: users[%d]: empty name", i)
		}
		if _, dup := names[user.Name]; dup {
			return fmt.Errorf("shadowsocks: duplicate user name %q", user.Name)
		}
		names[user.Name] = struct{}{}
		if err := checkKey(user.Password, keyLength); err != nil {
			return fmt.Errorf("shadowsocks: user %q password (uPSK): %w", user.Name, err)
		}
		if other, dup := keys[user.Password]; dup {
			if other == "" {
				return fmt.Errorf("shadowsocks: user %q password equals the server password", user.Name)
			}
			return fmt.Errorf("shadowsocks: users %q and %q share a password", other, user.Name)
		}
		keys[user.Password] = user.Name
	}
	return nil
}

func checkKey(key string, length int) error {
	if key == "" {
		return fmt.Errorf("missing")
	}
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("decode base64: %w", err)
	}
	if len(b) != length {
		return fmt.Errorf("bad key length, required %d bytes, got %d", length, len(b))
	}
	return nil
}

// userKey keys the users of a multi-user listener by their uPSK; the keys
// are validated by ValidateUsers.
func userKey(user C.InboundUser) (string, error) {
	return user.Secret, nil
}

// swapMultiService builds a multi-user service for the current users and
// makes it serve the new connections and packets. The connections already
// handed to the previous service keep running on it; a UDP session moves to
// the new service with its next packet (the client sees a new server
// session).
func (l *Listener) swapMultiService() error {
	users := l.users.Users()
	service, err := shadowaead_2022.NewMultiServiceWithPassword[string](l.config.Cipher, l.config.Password, l.udpTimeout, handshakeDone{&userGate{
		ListenerHandler: l.handler,
		users:           l.users,
		entries:         l.users.Entries(),
	}}, ntp.Now)
	if err != nil {
		return err
	}
	names := make([]string, len(users))
	passwords := make([]string, len(users))
	for i, user := range users {
		names[i], passwords[i] = user.Name, user.Secret
	}
	if err = service.UpdateUsersWithPasswords(names, passwords); err != nil {
		return err
	}
	l.service.Store(&serviceBox{service})
	return nil
}

// Users returns the current users (Name = name, Secret = uPSK); nil when the
// listener is not multi-user.
func (l *Listener) Users() []C.InboundUser {
	if l.users == nil {
		return nil
	}
	return l.users.Users()
}

// ReplaceUsers swaps the users of a multi-user (Shadowsocks 2022 with EIH)
// listener without closing it: the connections of the removed and changed
// users are closed, those of the other users are left alone. The library
// swaps its user table without a lock, so instead of updating the running
// service a new one is built and swapped in atomically.
func (l *Listener) ReplaceUsers(users []C.InboundUser) (inbounduser.Change, error) {
	if l.users == nil {
		return inbounduser.Change{}, fmt.Errorf("%w: a shadowsocks listener without users is single-user (users need a 2022-blake3-aes-* method and users in the configuration)", C.ErrInboundUsersUnsupported)
	}
	if err := inbounduser.NoFlow("shadowsocks", users); err != nil {
		return inbounduser.Change{}, err
	}
	ssUsers := make([]LC.ShadowsocksUser, len(users))
	for i, user := range users {
		ssUsers[i] = LC.ShadowsocksUser{Name: user.Name, Password: user.Secret}
	}
	if err := ValidateUsers(l.config.Cipher, l.config.Password, ssUsers); err != nil {
		return inbounduser.Change{}, fmt.Errorf("%w: %s", C.ErrInvalidInboundUser, err)
	}

	l.usersMu.Lock()
	defer l.usersMu.Unlock()
	// the previous service keeps the previous entries: a handshake it
	// completes from here on finds the entry revoked when the user was
	// removed or changed, and is dropped
	change, err := l.users.Replace(users)
	if err != nil {
		return change, err
	}
	return change, l.swapMultiService()
}

// userGate binds every connection of a multi service to the entry of its
// user, so that removing or re-keying the user closes it.
type userGate struct {
	*sing.ListenerHandler
	users   *inbounduser.Set[string]
	entries map[string]*inbounduser.Entry
}

func (g *userGate) bind(ctx context.Context, c io.Closer) (func(), bool) {
	user, _ := auth.UserFromContext[string](ctx)
	entry := g.entries[user]
	if entry == nil {
		return func() {}, true
	}
	return g.users.Bind(entry, c)
}

type rawConnKey struct{}

// withRawConn records the client connection for userGate: the connection
// the service hands to the handler wraps it, and closing that wrapper races
// with its writes.
func withRawConn(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(ctx, rawConnKey{}, conn)
}

// handshakeDone lifts the handshake deadline of the client connection (set
// in HandleConn) once the service has authenticated it and read its target,
// so a long-lived connection is never cut by it.
type handshakeDone struct {
	shadowsocks.Handler
}

func (h handshakeDone) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	if raw, ok := ctx.Value(rawConnKey{}).(net.Conn); ok {
		authStore.ClearHandshakeDeadline(raw)
	}
	return h.Handler.NewConnection(ctx, conn, metadata)
}

func (g *userGate) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	var closer io.Closer = conn
	if raw, ok := ctx.Value(rawConnKey{}).(net.Conn); ok {
		closer = raw
	}
	release, ok := g.bind(ctx, closer)
	if !ok {
		_ = conn.Close()
		return E.New("shadowsocks: user was removed")
	}
	defer release()
	return g.ListenerHandler.NewConnection(ctx, conn, metadata)
}

func (g *userGate) NewPacketConnection(ctx context.Context, conn network.PacketConn, metadata M.Metadata) error {
	release, ok := g.bind(ctx, conn)
	if !ok {
		_ = conn.Close()
		return E.New("shadowsocks: user was removed")
	}
	defer release()
	return g.ListenerHandler.NewPacketConnection(ctx, conn, metadata)
}
