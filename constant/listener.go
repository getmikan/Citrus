package constant

import (
	"context"
	"errors"
	"net"
)

type Listener interface {
	RawAddress() string
	Address() string
	Close() error
}

type MultiAddrListener interface {
	Close() error
	Config() string
	AddrList() (addrList []net.Addr)
}

type InboundListener interface {
	Name() string
	Listen(tunnel Tunnel) error
	Close() error
	Address() string
	RawAddress() string
	Config() InboundConfig
}

// InboundUserLister is implemented by the inbound listeners that know the
// complete list of their users, each as it appears in Metadata.InUser. The
// per-user traffic counters of the users that are no longer listed are
// dropped after a configuration reload.
type InboundUserLister interface {
	InboundUsers() []string
}

// InboundUser is a user of an inbound listener in a protocol-neutral form:
// Name is the user as it appears in Metadata.InUser (and in the per-user
// traffic counters), Secret is the credential and Flow is an optional
// protocol detail. How they map to a protocol:
//
//	vless                  Name = username, Secret = uuid, Flow = flow
//	trojan                 Name = username, Secret = password
//	anytls, trusttunnel    Name = user,     Secret = password
//	tuic (v5)              Name = uuid,     Secret = password
//	shadowsocks (2022 EIH) Name = name,     Secret = password (uPSK)
//	socks, http, mixed     Name = username, Secret = password
type InboundUser struct {
	Name   string `json:"name"`
	Secret string `json:"secret,omitempty"`
	Flow   string `json:"flow,omitempty"`
}

// InboundUserUpdater is implemented by the inbound listeners whose users can
// be replaced while they run, without closing the listener: handshakes after
// SetUsers returns use the new users, the established sessions of the users
// that were removed or whose credentials changed are closed, the others are
// left alone.
//
// Users returns the current users, with their secrets. SetUsers replaces all
// of them; every user must have a unique non-empty name and a valid unique
// secret (errors wrap ErrInvalidInboundUser), and a listener that cannot
// take users in its current mode returns an error wrapping
// ErrInboundUsersUnsupported. SameExceptUsers reports whether config differs
// from the configuration the listener was created with only in its users,
// so a configuration reload can call SetUsers instead of recreating it.
//
// Runtime changes live in memory: a configuration reload sets the users of
// the configuration again.
type InboundUserUpdater interface {
	Users() []InboundUser
	SetUsers(users []InboundUser) error
	SameExceptUsers(config InboundConfig) bool
}

var (
	// ErrInvalidInboundUser is wrapped by the validation errors of
	// InboundUserUpdater.SetUsers.
	ErrInvalidInboundUser = errors.New("invalid inbound user")
	// ErrInboundUsersUnsupported is wrapped by the errors of the listeners
	// that cannot change their users at runtime.
	ErrInboundUsersUnsupported = errors.New("inbound does not support runtime user updates")
)

type InboundConfig interface {
	Name() string
	Equal(config InboundConfig) bool
}

type InboundListenConfig interface {
	Listen(ctx context.Context, network, address string) (net.Listener, error)
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}
