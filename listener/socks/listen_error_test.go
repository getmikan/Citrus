package socks

import (
	"net"
	"testing"

	"github.com/metacubex/mihomo/adapter/inbound"
	LC "github.com/metacubex/mihomo/listener/config"

	"github.com/stretchr/testify/require"
)

// A configuration error found after the port is opened must not leave the
// port bound with nobody accepting: the corrected reload must be able to
// listen on it.
func TestNewWithConfigBadCertificateFreesPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	_, err = NewWithConfig(LC.AuthServer{
		Enable:      true,
		Listen:      addr,
		Certificate: "missing.crt",
		PrivateKey:  "missing.key",
	}, inbound.NewListenConfig(), nil, inbound.WithInName("test"))
	require.Error(t, err)

	l, err = net.Listen("tcp", addr)
	require.NoError(t, err, "the failed listener keeps the port")
	_ = l.Close()
}
