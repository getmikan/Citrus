//go:build linux

package outbound

import (
	"context"
	"encoding/json"
	"net"
	"syscall"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"

	"github.com/Nemu-x/desync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hopLimitListener listens on IPv6 loopback with hop limit hl, which the
// SYN-ACK inherits, so the loopback path looks like 128 - hl hops (for hl
// above 96) to the client.
func hopLimitListener(t *testing.T, hl int) net.Listener {
	t.Helper()
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var opErr error
		if err := c.Control(func(fd uintptr) {
			opErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, hl)
		}); err != nil {
			return err
		}
		return opErr
	}}
	ln, err := lc.Listen(context.Background(), "tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	withIPv6(t)
	return ln
}

func hopRecording(t *testing.T, conn net.Conn) int {
	t.Helper()
	dc, ok := N.UnwrapWriter(conn).(*desyncConn)
	require.True(t, ok)
	raw, err := dc.socket.(syscall.Conn).SyscallConn()
	require.NoError(t, err)
	var on int
	var opErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		on, opErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6RecvHopLimit)
	}))
	require.NoError(t, opErr)
	return on
}

// The outbound's dial prepares the socket with ControlAutoTTL: the TTL of
// the SYN-ACK (hop limit 120: 8 hops) gives the fake TTL 7, which the API
// reports, and the recording is off once it was read.
func TestDesyncLinuxAutoTTL(t *testing.T) {
	ln := hopLimitListener(t, 120)
	record := captureClientHello(t)
	got := readFirst(ln, len(record))

	d := newTestDesync(t, DesyncOption{TLSRec: "", Fake: &DesyncFakeOption{AutoTTL: &DesyncAutoTTLOption{}}})
	withVerifiableFake(d, record, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, desyncMetadata(ln.Addr()))
	require.NoError(t, err)
	defer conn.Close()
	assert.Equal(t, 1, hopRecording(t, conn), "dialed with ControlAutoTTL")

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(record)
	require.NoError(t, err)
	assert.Equal(t, record, <-got)
	assert.Equal(t, 0, hopRecording(t, conn), "the recording is off after the fake")

	raw, err := d.MarshalJSON()
	require.NoError(t, err)
	var v struct {
		Desync struct {
			TCP struct {
				Fake struct {
					LastTTL struct {
						TTL  int  `json:"ttl"`
						Auto bool `json:"auto"`
					} `json:"last-ttl"`
				} `json:"fake"`
			} `json:"tcp"`
		} `json:"desync"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	assert.Equal(t, 7, v.Desync.TCP.Fake.LastTTL.TTL)
	assert.True(t, v.Desync.TCP.Fake.LastTTL.Auto, "derived from the path")
}

// A connection that does not start with a ClientHello gets no fake; the
// outbound turns the hop limit recording off itself.
func TestDesyncLinuxAutoTTLNonTLS(t *testing.T) {
	ln := hopLimitListener(t, 120)
	request := []byte("GET / HTTP/1.1\r\n\r\n")
	got := readFirst(ln, len(request))
	d := newTestDesync(t, DesyncOption{Fake: &DesyncFakeOption{TTL: 4, AutoTTL: &DesyncAutoTTLOption{}}})
	conn, err := d.DialContext(context.Background(), desyncMetadata(ln.Addr()))
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, 1, hopRecording(t, conn))
	_, err = conn.Write(request)
	require.NoError(t, err)
	assert.Equal(t, request, <-got)
	assert.Equal(t, 0, hopRecording(t, conn))
	assert.Equal(t, int32(0), d.lastFakeTTL.Load())
}

// Without auto-ttl the socket is not prepared.
func TestDesyncLinuxNoAutoTTLControl(t *testing.T) {
	ln := hopLimitListener(t, 120)
	_ = readFirst(ln, 1)
	d := newTestDesync(t, DesyncOption{Fake: &DesyncFakeOption{TTL: 4}})
	conn, err := d.DialContext(context.Background(), desyncMetadata(ln.Addr()))
	require.NoError(t, err)
	defer conn.Close()
	assert.Equal(t, 0, hopRecording(t, conn))
	_, err = desync.ObserveHops(N.UnwrapWriter(conn).(*desyncConn).socket)
	assert.ErrorIs(t, err, desync.ErrAutoTTLUnobserved)
}
