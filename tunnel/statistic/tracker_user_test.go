package statistic_test

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func userMetadata(inbound, user, src string) *C.Metadata {
	return &C.Metadata{
		NetWork: C.TCP,
		Type:    C.INNER,
		SrcIP:   netip.MustParseAddr(src),
		SrcPort: 12345,
		DstIP:   netip.MustParseAddr("1.2.3.4"),
		DstPort: 443,
		InName:  inbound,
		InUser:  user,
	}
}

// uniqueInbound returns a fresh inbound name: the counters of
// statistic.DefaultManager are global and cumulative, so every run of a test
// (-count=N) needs its own keys.
func uniqueInbound(name string) string {
	return name + "-" + utils.NewUUIDV4().String()
}

func userStat(t *testing.T, inbound, user string) statistic.UserStat {
	t.Helper()
	s, ok := statistic.DefaultManager.Users().Get(statistic.UserKey{Inbound: inbound, User: user})
	require.True(t, ok, "no counter for %s/%s", inbound, user)
	return s
}

// tcpPair returns a tracked conn over a pipe and the remote end of the pipe.
func tcpPair(t *testing.T, metadata *C.Metadata, peek int64) (C.Conn, net.Conn) {
	local, remote := net.Pipe()
	t.Cleanup(func() {
		_ = local.Close()
		_ = remote.Close()
	})
	conn := outbound.NewConn(local, outbound.NewDirect())
	return statistic.NewTCPTracker(conn, statistic.DefaultManager, metadata, nil, peek, 0, true), remote
}

func TestTCPTrackerUserCounting(t *testing.T) {
	inbound := uniqueInbound("tcp-tracker-test")
	tracker, remote := tcpPair(t, userMetadata(inbound, "alice", "::ffff:10.1.1.1"), 7)

	go func() {
		b := make([]byte, 64)
		_, _ = io.ReadFull(remote, b[:10]) // Write
		_, _ = io.ReadFull(remote, b[:20]) // WriteBuffer
		_, _ = remote.Write(make([]byte, 30))
		_, _ = remote.Write(make([]byte, 40))
	}()

	_, err := tracker.Write(make([]byte, 10))
	require.NoError(t, err)
	buffer := buf.NewSize(20)
	buffer.Extend(20)
	require.NoError(t, tracker.WriteBuffer(buffer))
	_, err = io.ReadFull(tracker, make([]byte, 30))
	require.NoError(t, err)
	rb := buf.NewSize(64)
	defer rb.Release()
	require.NoError(t, tracker.ReadBuffer(rb))

	s := userStat(t, inbound, "alice")
	assert.Equal(t, int64(7+10+20), s.Up, "peek + Write + WriteBuffer")
	assert.Equal(t, int64(30+rb.Len()), s.Down)
	assert.Equal(t, int64(1), s.Conns)
	require.Len(t, s.IPs, 1)
	assert.Equal(t, netip.MustParseAddr("10.1.1.1"), s.IPs[0].IP, "a mapped IPv4 address is unmapped")

	// the splice/copy path reports through the count functions
	_, readCounters := tracker.(interface {
		UnwrapReader() (io.Reader, []N.CountFunc)
	}).UnwrapReader()
	_, writeCounters := tracker.(interface {
		UnwrapWriter() (io.Writer, []N.CountFunc)
	}).UnwrapWriter()
	for _, f := range readCounters {
		f(1000)
	}
	for _, f := range writeCounters {
		f(500)
	}
	s2 := userStat(t, inbound, "alice")
	assert.Equal(t, s.Up+500, s2.Up)
	assert.Equal(t, s.Down+1000, s2.Down)

	// Close is idempotent: the connection and the address are released once
	require.NoError(t, tracker.Close())
	_ = tracker.Close()
	s = userStat(t, inbound, "alice")
	assert.Equal(t, int64(0), s.Conns)
	require.Len(t, s.IPs, 1)
	assert.Equal(t, int64(0), s.IPs[0].Conns)
}

func TestTrackerWithoutUser(t *testing.T) {
	inbound := uniqueInbound("tracker-anonymous-test")
	before := len(statistic.DefaultManager.Users().SnapshotFunc(func(k statistic.UserKey) bool { return k.Inbound == inbound }))
	tracker, _ := tcpPair(t, userMetadata(inbound, "", "10.1.1.2"), 0)
	defer tracker.Close()
	after := len(statistic.DefaultManager.Users().SnapshotFunc(func(k statistic.UserKey) bool { return k.Inbound == inbound }))
	assert.Equal(t, before, after)
	assert.Equal(t, 0, after)
}

func TestTrackerUserStatsDisabled(t *testing.T) {
	inbound := uniqueInbound("tracker-disabled-test")
	statistic.SetUserStatsEnabled(false)
	defer statistic.SetUserStatsEnabled(true)
	tracker, _ := tcpPair(t, userMetadata(inbound, "alice", "10.1.1.3"), 5)
	defer tracker.Close()
	_, ok := statistic.DefaultManager.Users().Get(statistic.UserKey{Inbound: inbound, User: "alice"})
	assert.False(t, ok)
}

// tcpClientPair returns both ends of a loopback TCP connection.
func tcpClientPair(t *testing.T) (net.Conn, net.Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	local := <-accepted
	require.NotNil(t, local)
	return client, local
}

// TestTCPTrackerRelay checks the exact counts of a relay through a tracker,
// to a client behind a pipe (copied buffer by buffer) and behind a socket
// (spliced on Linux).
func TestTCPTrackerRelay(t *testing.T) {
	for name, clientPair := range map[string]func(*testing.T) (net.Conn, net.Conn){
		"pipe": func(*testing.T) (net.Conn, net.Conn) { return net.Pipe() },
		"tcp":  tcpClientPair,
	} {
		t.Run(name, func(t *testing.T) {
			inbound := uniqueInbound("tcp-relay-test")
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()
			const upSize, downSize = 300_000, 700_000
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_, _ = io.CopyN(io.Discard, c, upSize)
				_, _ = c.Write(make([]byte, downSize))
			}()
			raw, err := net.Dial("tcp", ln.Addr().String())
			require.NoError(t, err)
			globalUp, globalDown := statistic.DefaultManager.Total()
			tracker := statistic.NewTCPTracker(outbound.NewConn(raw, outbound.NewDirect()), statistic.DefaultManager,
				userMetadata(inbound, "bob", "10.1.1.4"), nil, 0, 0, true)

			client, local := clientPair(t)
			go func() {
				_, _ = client.Write(make([]byte, upSize))
				_, _ = io.CopyN(io.Discard, client, downSize)
				_ = client.Close()
			}()
			N.Relay(local, tracker)

			s := userStat(t, inbound, "bob")
			assert.Equal(t, int64(upSize), s.Up)
			assert.Equal(t, int64(downSize), s.Down)
			assert.Equal(t, int64(0), s.Conns)
			assert.Equal(t, int64(upSize), tracker.Info().UploadTotal.Load())
			assert.Equal(t, int64(downSize), tracker.Info().DownloadTotal.Load())
			globalUpAfter, globalDownAfter := statistic.DefaultManager.Total()
			assert.Equal(t, int64(upSize), globalUpAfter-globalUp)
			assert.Equal(t, int64(downSize), globalDownAfter-globalDown)
		})
	}
}

var errStreamClosed = errors.New("stream closed")

// deliverThenFailConn is the client side of a multiplexed stream that takes
// the bytes of a write and then reports the write as failed, as an HTTP/2
// stream does when the client resets it right after the DATA frame went out.
type deliverThenFailConn struct {
	net.Conn // the reading half: blocks until the relay closes it

	mu        sync.Mutex
	delivered int
}

func (c *deliverThenFailConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.delivered += len(p)
	return len(p), errStreamClosed
}

func (c *deliverThenFailConn) Delivered() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.delivered
}

// TestTCPTrackerRelayFailedWriteIsCounted: the relay copy counts a buffer
// after its write succeeded; a write that delivered the bytes but reported an
// error must still be counted, in the per-connection, per-user and global
// totals alike.
func TestTCPTrackerRelayFailedWriteIsCounted(t *testing.T) {
	inbound := uniqueInbound("tcp-relay-failed-write-test")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	const downSize = 9_000
	served := make(chan struct{})
	defer close(served)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write(make([]byte, downSize))
		<-served // keep the connection open: the copy ends on the failed write only
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	_, globalDown := statistic.DefaultManager.Total()
	tracker := statistic.NewTCPTracker(outbound.NewConn(raw, outbound.NewDirect()), statistic.DefaultManager,
		userMetadata(inbound, "dave", "10.1.1.7"), nil, 0, 0, true)

	reader, peer := net.Pipe()
	defer peer.Close()
	client := &deliverThenFailConn{Conn: reader}
	N.Relay(client, tracker)

	delivered := int64(client.Delivered())
	require.Positive(t, delivered)
	assert.Equal(t, delivered, tracker.Info().DownloadTotal.Load(), "connection")
	assert.Equal(t, delivered, userStat(t, inbound, "dave").Down, "user")
	_, globalDownAfter := statistic.DefaultManager.Total()
	assert.Equal(t, delivered, globalDownAfter-globalDown, "global")
}

func TestUDPTrackerUserCounting(t *testing.T) {
	inbound := uniqueInbound("udp-tracker-test")
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, addr, err := server.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = server.WriteTo(b[:n*2], addr) // answers twice as much
		}
	}()

	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	metadata := userMetadata(inbound, "carol", "10.1.1.5")
	metadata.NetWork = C.UDP
	tracker := statistic.NewUDPTracker(outbound.NewPacketConn(raw, outbound.NewDirect()), statistic.DefaultManager, metadata, nil, 0, 0, true)

	b := make([]byte, 2048)
	_, err = tracker.WriteTo(make([]byte, 100), server.LocalAddr())
	require.NoError(t, err)
	n, _, err := tracker.ReadFrom(b)
	require.NoError(t, err)
	assert.Equal(t, 200, n)
	_, err = tracker.WriteTo(make([]byte, 50), server.LocalAddr())
	require.NoError(t, err)
	data, put, _, err := tracker.WaitReadFrom()
	require.NoError(t, err)
	assert.Len(t, data, 100)
	if put != nil {
		put()
	}

	s := userStat(t, inbound, "carol")
	assert.Equal(t, int64(150), s.Up)
	assert.Equal(t, int64(300), s.Down)
	assert.Equal(t, int64(1), s.Conns)

	require.NoError(t, tracker.Close())
	_ = tracker.Close()
	s = userStat(t, inbound, "carol")
	assert.Equal(t, int64(0), s.Conns)
}

func TestInternalTrackersAreNotAttributed(t *testing.T) {
	// the trackers of the DNS dialer and of dialer-proxy chains (pushToManager
	// false) sit under a tracker that already counts the user
	inbound := uniqueInbound("internal-tracker-test")
	local, remote := net.Pipe()
	defer remote.Close()
	tracker := statistic.NewTCPTracker(outbound.NewConn(local, outbound.NewDirect()), statistic.DefaultManager,
		userMetadata(inbound, "alice", "10.1.1.6"), nil, 10, 0, false)
	defer tracker.Close()
	_, ok := statistic.DefaultManager.Users().Get(statistic.UserKey{Inbound: inbound, User: "alice"})
	assert.False(t, ok)
}

// The function set with SetOnLeave sees every tracked connection once as it
// ends, with its metadata and totals.
func TestOnLeave(t *testing.T) {
	inbound := uniqueInbound("leave")
	var mu sync.Mutex
	var seen []statistic.Tracker
	statistic.DefaultManager.SetOnLeave(func(c statistic.Tracker) {
		if c.Info().Metadata.InName != inbound {
			return
		}
		mu.Lock()
		seen = append(seen, c)
		mu.Unlock()
	})
	t.Cleanup(func() { statistic.DefaultManager.SetOnLeave(nil) })

	conn, remote := tcpPair(t, userMetadata(inbound, "alice", "10.0.0.1"), 0)
	go func() { _, _ = remote.Write(make([]byte, 300)) }()
	_, err := io.ReadFull(conn, make([]byte, 300))
	require.NoError(t, err)
	go func() { _, _ = io.ReadFull(remote, make([]byte, 100)) }()
	_, err = conn.Write(make([]byte, 100))
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	_ = conn.Close() // a second Close reports nothing more

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, seen, 1)
	assert.Equal(t, "alice", seen[0].Info().Metadata.InUser)
	assert.Equal(t, int64(100), seen[0].Info().UploadTotal.Load())
	assert.Equal(t, int64(300), seen[0].Info().DownloadTotal.Load())
}
