package inbound_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// limitsInbound is the name of the inbound of the current test, fresh for
// every test so that the counters start at zero (also with -count).
var limitsInbound string

type limitsEnv struct {
	t      *testing.T
	proxy  string
	server netip.AddrPort
}

// newLimitsEnv starts a SOCKS5 inbound with password users in front of the
// real tunnel (DIRECT) and a sized server behind it.
func newLimitsEnv(t *testing.T, users ...string) *limitsEnv {
	tunnel.UpdateProxies(map[string]C.Proxy{"DIRECT": adapter.NewProxy(outbound.NewDirect())}, nil)
	tunnel.OnRunning()
	limitsInbound = fmt.Sprintf("socks-user-limits-%d", time.Now().UnixNano())
	var auth inbound.AuthUsers
	for _, u := range users {
		auth = append(auth, inbound.AuthUser{Username: u, Password: u + "-pass"})
	}
	in, err := inbound.NewSocks(&inbound.SocksOption{
		BaseOption: inbound.BaseOption{NameStr: limitsInbound, Listen: "127.0.0.1", Port: "0"},
		Users:      auth,
	})
	require.NoError(t, err)
	require.NoError(t, in.Listen(tunnel.Tunnel))
	t.Cleanup(func() { _ = in.Close() })
	return &limitsEnv{t: t, proxy: in.Address(), server: startSizedServer(t)}
}

func (e *limitsEnv) limit(l statistic.UserLimit) {
	e.t.Helper()
	l.Inbound = limitsInbound
	um := statistic.DefaultManager.Users()
	require.NoError(e.t, um.SetLimit(l))
	e.t.Cleanup(func() { um.DeleteLimit(l.Key()) })
}

// open connects to the sized server through the inbound as user, from src.
func (e *limitsEnv) open(user, src string) net.Conn {
	e.t.Helper()
	d := net.Dialer{Timeout: 5 * time.Second}
	if src != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(src)}
	}
	conn, err := d.Dial("tcp", e.proxy)
	require.NoError(e.t, err)
	e.t.Cleanup(func() { _ = conn.Close() })
	_, err = socks5.ClientHandshake(conn, socks5.ParseAddrToSocksAddr(net.TCPAddrFromAddrPort(e.server)), socks5.CmdConnect,
		&socks5.User{Username: user, Password: user + "-pass"})
	require.NoError(e.t, err)
	return conn
}

// closedByTunnel reports whether the tunnel closed conn (a rejected
// connection) rather than keeping it open.
func closedByTunnel(conn net.Conn) bool {
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	defer conn.SetReadDeadline(time.Time{})
	_, err := conn.Read(make([]byte, 1))
	return err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
}

// transfer sends up bytes and receives down bytes over a new connection.
func (e *limitsEnv) transfer(user string, up, down int) error {
	conn := e.open(user, "")
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(up))
	binary.BigEndian.PutUint32(hdr[4:], uint32(down))
	if _, err := conn.Write(append(hdr[:], make([]byte, up)...)); err != nil {
		return err
	}
	// the server closes after the download, once it read the whole upload
	n, err := io.Copy(io.Discard, conn)
	if err == nil && n != int64(down) {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func limitsStat(t *testing.T, user string) statistic.UserStat {
	t.Helper()
	s, ok := statistic.DefaultManager.Users().Get(statistic.UserKey{Inbound: limitsInbound, User: user})
	require.True(t, ok)
	return s
}

func TestInboundUserLimitMaxConns(t *testing.T) {
	e := newLimitsEnv(t, "alice")
	e.limit(statistic.UserLimit{User: "alice", MaxConns: 2})
	c1 := e.open("alice", "")
	c2 := e.open("alice", "")
	assert.False(t, closedByTunnel(c1))
	assert.False(t, closedByTunnel(c2))
	assert.True(t, closedByTunnel(e.open("alice", "")), "the third connection is rejected")
	s := limitsStat(t, "alice")
	assert.Equal(t, int64(2), s.Conns)
	assert.Equal(t, int64(1), s.RejectReasons[statistic.RejectMaxConns])

	_ = c1.Close()
	assert.Eventually(t, func() bool { return limitsStat(t, "alice").Conns == 1 }, 5*time.Second, 20*time.Millisecond)
	assert.False(t, closedByTunnel(e.open("alice", "")))
}

func TestInboundUserLimitMaxIPs(t *testing.T) {
	e := newLimitsEnv(t, "bob")
	e.limit(statistic.UserLimit{User: "bob", MaxIPs: 2})
	assert.False(t, closedByTunnel(e.open("bob", "127.0.0.2")))
	assert.False(t, closedByTunnel(e.open("bob", "127.0.0.3")))
	assert.True(t, closedByTunnel(e.open("bob", "127.0.0.4")), "a third address is rejected")
	assert.False(t, closedByTunnel(e.open("bob", "127.0.0.2")), "a known address keeps working")
	s := limitsStat(t, "bob")
	assert.Equal(t, int64(1), s.RejectReasons[statistic.RejectMaxIPs])
	assert.Len(t, s.IPs, 2)
}

func TestInboundUserLimitQuota(t *testing.T) {
	e := newLimitsEnv(t, "carol")
	e.limit(statistic.UserLimit{User: "carol", Quota: 300_000})
	require.NoError(t, e.transfer("carol", 1000, 200_000))
	// the next transfer crosses the quota and is cut
	assert.Error(t, e.transfer("carol", 1000, 2_000_000))
	assert.True(t, closedByTunnel(e.open("carol", "")), "over the quota, new connections are rejected")
	st, _ := statistic.DefaultManager.Users().GetLimit(statistic.UserKey{Inbound: limitsInbound, User: "carol"})
	assert.True(t, st.QuotaExceeded)
	assert.Equal(t, int64(0), *st.Remaining)
	assert.Equal(t, int64(1), limitsStat(t, "carol").RejectReasons[statistic.RejectQuota])

	statistic.DefaultManager.Users().ResetQuota(func(k statistic.UserKey) bool { return k.Inbound == limitsInbound })
	require.NoError(t, e.transfer("carol", 1000, 200_000), "the reset admits the user again")
}

func TestInboundUserLimitExpire(t *testing.T) {
	e := newLimitsEnv(t, "dave")
	e.limit(statistic.UserLimit{User: "dave", ExpireAt: time.Now().Unix() + 2})
	conn := e.open("dave", "")
	assert.False(t, closedByTunnel(conn))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Read(make([]byte, 1))
	assert.False(t, errors.Is(err, os.ErrDeadlineExceeded), "the open connection is closed at expire-at")
	assert.True(t, closedByTunnel(e.open("dave", "")))
	assert.Equal(t, int64(1), limitsStat(t, "dave").RejectReasons[statistic.RejectExpired])
}

// TestInboundUserLimitSpeed moves 6 MB down and 3 MB up through the tunnel
// over two connections of a user limited to 2 MB/s down and 1 MB/s up.
func TestInboundUserLimitSpeed(t *testing.T) {
	e := newLimitsEnv(t, "erin")
	const rateDown, rateUp = 2_000_000, 1_000_000
	e.limit(statistic.UserLimit{User: "erin", SpeedDown: rateDown, SpeedUp: rateUp})
	measure := func(up, down int) time.Duration {
		start := time.Now()
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				assert.NoError(t, e.transfer("erin", up, down))
			}()
		}
		wg.Wait()
		return time.Since(start)
	}
	check := func(elapsed time.Duration, bytes, rate int64) {
		want := time.Duration(float64(bytes)/float64(rate)*float64(time.Second)) - 100*time.Millisecond
		t.Logf("%d bytes at %d B/s through the tunnel: %s (ideal %s, %.1f%% off)", bytes, rate, elapsed.Round(time.Millisecond), want,
			100*(elapsed.Seconds()-want.Seconds())/want.Seconds())
		assert.InDelta(t, want.Seconds(), elapsed.Seconds(), want.Seconds()/10)
	}
	check(measure(0, 3_000_000), 6_000_000, rateDown)
	check(measure(1_500_000, 0), 3_000_000+16, rateUp)
}
