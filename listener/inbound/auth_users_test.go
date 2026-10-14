package inbound_test

import (
	"errors"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/require"
)

// An account with an empty username is refused: the empty name means "no
// user" to IN-USER, the user limits and the session binding.
func TestAuthInboundsRejectEmptyUsername(t *testing.T) {
	users := inbound.AuthUsers{{Username: "alice", Password: "a"}, {Username: "", Password: "secret"}}
	base := inbound.BaseOption{NameStr: "empty-user", Listen: "127.0.0.1", Port: "0"}
	for name, build := range map[string]func() error{
		"socks": func() error {
			_, err := inbound.NewSocks(&inbound.SocksOption{BaseOption: base, Users: users})
			return err
		},
		"http": func() error {
			_, err := inbound.NewHTTP(&inbound.HTTPOption{BaseOption: base, Users: users})
			return err
		},
		"mixed": func() error {
			_, err := inbound.NewMixed(&inbound.MixedOption{BaseOption: base, Users: users})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := build()
			require.Error(t, err)
			require.True(t, errors.Is(err, C.ErrInvalidInboundUser), "%v", err)
		})
	}
}
