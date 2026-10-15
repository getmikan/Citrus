//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingDialer stands for the dialer-proxy and counts what goes through it.
type countingDialer struct {
	dials, listens atomic.Int32
}

func (d *countingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.dials.Add(1)
	return nil, errors.New("fake dialer")
}

func (d *countingDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	d.listens.Add(1)
	return nil, errors.New("fake dialer")
}

func TestTailscaleUDPDisabled(t *testing.T) {
	assert.False(t, tailscaleUDPDisabled(TailscaleOption{}))
	assert.True(t, tailscaleUDPDisabled(TailscaleOption{BasicOption: BasicOption{DialerProxy: "ss1"}}))
	// an API dialer replaces the dialer-proxy, and can open UDP sockets itself
	assert.False(t, tailscaleUDPDisabled(TailscaleOption{BasicOption: BasicOption{DialerProxy: "ss1", DialerForAPI: &countingDialer{}}}))
}

func TestTailscalePacketListenerWithoutUDP(t *testing.T) {
	d := &countingDialer{}
	listen := tailscalePacketListener("test", true, d)
	for _, network := range []string{"udp4", "udp6", "udp", "ip4:icmp"} {
		pc, err := listen(context.Background(), network, ":0")
		require.NoError(t, err, network)

		n, err := pc.WriteTo([]byte("stun"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 3478})
		assert.NoError(t, err)
		assert.Equal(t, 4, n)
		_, isUDPAddr := pc.LocalAddr().(*net.UDPAddr)
		assert.True(t, isUDPAddr)
		assert.Error(t, pc.SetReadDeadline(time.Now()))

		read := make(chan error, 1)
		go func() {
			_, _, err := pc.ReadFrom(make([]byte, 1500))
			read <- err
		}()
		select {
		case err := <-read:
			t.Fatalf("read returned before close: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
		require.NoError(t, pc.Close())
		assert.ErrorIs(t, <-read, net.ErrClosed)
		assert.ErrorIs(t, pc.Close(), net.ErrClosed)
		_, err = pc.WriteTo([]byte("x"), &net.UDPAddr{})
		assert.ErrorIs(t, err, net.ErrClosed)
	}
	// nothing went to the dialer-proxy, and nothing around it
	assert.Zero(t, d.listens.Load())
	assert.Zero(t, d.dials.Load())

	// without a dialer-proxy the dialer opens the socket, as before
	_, err := tailscalePacketListener("test", false, d)(context.Background(), "udp4", ":0")
	assert.Error(t, err)
	assert.Equal(t, int32(1), d.listens.Load())
}

func TestTailscaleWithDialerProxy(t *testing.T) {
	// the proxy does not exist (and there is no tunnel): any use of the
	// dialer-proxy for UDP would fail, as the empty destination did before
	ts, err := NewTailscale(TailscaleOption{
		BasicOption: BasicOption{DialerProxy: "missing"},
		Name:        "ts-dialer-proxy-test",
		StateDir:    "tailscale-dialer-proxy-test",
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, ts.Close()) })

	pc, err := ts.server.SystemPacketListener(context.Background(), "udp4", ":0")
	require.NoError(t, err)
	_, isNoUDP := pc.(*tailscaleNoUDPConn)
	assert.True(t, isNoUDP)
	assert.NoError(t, pc.Close())

	// TCP (control plane, DERP) still goes through the dialer-proxy
	_, err = ts.server.SystemDialer(context.Background(), "tcp", "192.0.2.1:443")
	assert.ErrorContains(t, err, "tunnel is invalid")
}
