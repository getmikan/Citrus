package trojan

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	LC "github.com/metacubex/mihomo/listener/config"

	"github.com/stretchr/testify/require"
)

// failingListener fails every Accept with an error that is not net.ErrClosed,
// as a failed handshake listener does, and counts the calls.
type failingListener struct {
	net.Listener
	calls atomic.Int64
}

func (l *failingListener) Accept() (net.Conn, error) {
	l.calls.Add(1)
	return nil, errors.New("accept failed")
}

type failingListenConfig struct{ l *failingListener }

func (c *failingListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	raw, err := inbound.NewListenConfig().Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	c.l = &failingListener{Listener: raw}
	return c.l, nil
}

func (c *failingListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return inbound.NewListenConfig().ListenPacket(ctx, network, address)
}

// The accept loop used to retry a failing Accept without pause, at 100% CPU,
// until the listener was closed.
func TestAcceptLoopBacksOff(t *testing.T) {
	lc := &failingListenConfig{}
	sl, err := New(LC.TrojanServer{Enable: true, Listen: "127.0.0.1:0", AllowInsecure: true}, lc, nil)
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)
	// 5+10+20+40+80ms of back-off fit in 200ms
	require.LessOrEqual(t, lc.l.calls.Load(), int64(10), "the accept loop spins")

	require.NoError(t, sl.Close())
	time.Sleep(1100 * time.Millisecond) // the longest back-off
	calls := lc.l.calls.Load()
	time.Sleep(1100 * time.Millisecond)
	require.Equal(t, calls, lc.l.calls.Load(), "the accept loop outlived Close")
}
