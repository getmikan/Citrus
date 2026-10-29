package anytls

import (
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/internal/porttest"

	"github.com/stretchr/testify/require"
)

func TestNewInsecureRejectedFreesPort(t *testing.T) {
	addr := porttest.FreeAddr(t)
	_, err := New(LC.AnyTLSServer{Enable: true, Listen: addr}, inbound.NewListenConfig(), nil)
	require.ErrorContains(t, err, "disallow using AnyTLS")
	porttest.RequireFree(t, "tcp", addr)
}

// The cleanup closes the first listener while its accept goroutine runs: with
// a named result sl, nil by then, that goroutine panicked.
func TestNewLaterAddressFailsFreesEarlier(t *testing.T) {
	first := porttest.FreeAddr(t)
	_, err := New(LC.AnyTLSServer{
		Enable:        true,
		Listen:        first + "," + porttest.BusyAddr(t, "tcp"),
		AllowInsecure: true,
	}, inbound.NewListenConfig(), nil)
	require.Error(t, err)
	porttest.RequireFree(t, "tcp", first)
	time.Sleep(100 * time.Millisecond) // for the accept goroutine to see the close
}
