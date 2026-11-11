package http

import (
	"testing"

	"github.com/metacubex/mihomo/adapter/inbound"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/internal/porttest"

	"github.com/stretchr/testify/require"
)

// A configuration error found after the port is opened must not leave the
// port bound with nobody accepting: the corrected reload must be able to
// listen on it.
func TestNewWithConfigBadCertificateFreesPort(t *testing.T) {
	addr := porttest.FreeAddr(t)
	_, err := NewWithConfig(LC.AuthServer{
		Enable:      true,
		Listen:      addr,
		Certificate: "missing.crt",
		PrivateKey:  "missing.key",
	}, inbound.NewListenConfig(), nil, inbound.WithInName("test"))
	require.Error(t, err)
	porttest.RequireFree(t, "tcp", addr)
}
