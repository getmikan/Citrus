package config

import (
	"testing"

	"github.com/metacubex/mihomo/component/auth"

	"github.com/stretchr/testify/require"
)

func TestParseAuthentication(t *testing.T) {
	users, err := parseAuthentication([]string{"alice:a", "bob:b:c", "no-colon"})
	require.NoError(t, err)
	require.Equal(t, []auth.AuthUser{{User: "alice", Pass: "a"}, {User: "bob", Pass: "b:c"}}, users)

	// the empty name means "no user" to IN-USER, the limits and revocation
	_, err = parseAuthentication([]string{"alice:a", ":secret"})
	require.ErrorContains(t, err, "authentication[1]: empty user name")
}
