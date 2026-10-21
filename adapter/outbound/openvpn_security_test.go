package outbound

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenVPNRequiresServerIdentityPolicy(t *testing.T) {
	base := OpenVPNOption{Name: "vpn", Server: "vpn.example", Port: 1194}
	_, err := NewOpenVPN(base)
	require.ErrorContains(t, err, "server identity is not configured")

	conflict := base
	conflict.VerifyServerName = true
	conflict.SkipServerIdentityCheck = true
	_, err = NewOpenVPN(conflict)
	require.ErrorContains(t, err, "cannot be combined")
}
