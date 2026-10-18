package statistic_test

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setLimit(t *testing.T, l statistic.UserLimit) {
	t.Helper()
	um := statistic.DefaultManager.Users()
	require.NoError(t, um.SetLimit(l))
	t.Cleanup(func() { um.DeleteLimit(l.Key()) })
}

// relayThrough opens a tracked TCP connection of the user to a local server
// that reads up bytes and then sends down bytes, and relays a client through
// it like the tunnel does.
func relayThrough(t *testing.T, inbound, user string, up, down int64) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.CopyN(io.Discard, c, up)
		_, _ = io.CopyN(c, zeroReader{}, down)
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	tracker := statistic.NewTCPTracker(outbound.NewConn(raw, outbound.NewDirect()), statistic.DefaultManager,
		userMetadata(inbound, user, "10.2.2.2"), nil, 0, 0, true)

	// a real socket on the client side too, so that the relay could splice
	cl, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer cl.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		client, err := net.Dial("tcp", cl.Addr().String())
		if err != nil {
			return
		}
		defer client.Close()
		go func() { _, _ = io.CopyN(client, zeroReader{}, up) }()
		_, _ = io.CopyN(io.Discard, client, down)
	}()
	local, err := cl.Accept()
	require.NoError(t, err)
	relayed := make(chan struct{})
	go func() {
		defer close(relayed)
		N.Relay(local, tracker)
	}()
	<-done
	_ = local.Close()
	_ = tracker.Close()
	// the relay counts a write after it returns: wait for it, or the last
	// bytes may not be in the user counters yet when the caller reads them
	<-relayed
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) { return len(b), nil } // the content does not matter

func assertRate(t *testing.T, elapsed time.Duration, bytes, rate int64) {
	t.Helper()
	// the bucket starts with 100 ms of burst
	want := time.Duration(float64(bytes)/float64(rate)*float64(time.Second)) - 100*time.Millisecond
	t.Logf("%d bytes at %d B/s: %s (ideal %s, %.1f%% off)", bytes, rate, elapsed.Round(time.Millisecond), want,
		100*(elapsed.Seconds()-want.Seconds())/want.Seconds())
	assert.InDelta(t, want.Seconds(), elapsed.Seconds(), want.Seconds()/10, "took %s, want %s (±10%%)", elapsed, want)
}

// TestTrackerSpeedLimit moves 6 MB down and 3 MB up over two connections of
// one user that share a download limit of 2 MB/s and an upload limit of
// 1 MB/s: about 3 s each way.
func TestTrackerSpeedLimit(t *testing.T) {
	inbound := fmt.Sprintf("tracker-speed-test-%d", time.Now().UnixNano()) // fresh counters per run
	const rateDown, rateUp = 2_000_000, 1_000_000
	setLimit(t, statistic.UserLimit{Inbound: inbound, User: "alice", SpeedDown: rateDown})
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); relayThrough(t, inbound, "alice", 1000, 3_000_000) }()
	}
	wg.Wait()
	assertRate(t, time.Since(start), 6_000_000, rateDown)

	setLimit(t, statistic.UserLimit{Inbound: inbound, User: "bob", SpeedUp: rateUp})
	start = time.Now()
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); relayThrough(t, inbound, "bob", 1_500_000, 1000) }()
	}
	wg.Wait()
	assertRate(t, time.Since(start), 3_000_000, rateUp)

	s := userStat(t, inbound, "alice")
	assert.Equal(t, int64(6_000_000), s.Down)
	s = userStat(t, inbound, "bob")
	assert.Equal(t, int64(3_000_000), s.Up)
}

// TestTrackerUnlimitedIsFast checks that the same transfer without a limit is
// not slowed down.
func TestTrackerUnlimitedIsFast(t *testing.T) {
	start := time.Now()
	relayThrough(t, "tracker-unlimited-test", "alice", 1000, 6_000_000)
	assert.Less(t, time.Since(start), time.Second)
}

func TestTrackerUnwrapWithSpeedLimit(t *testing.T) {
	const inbound = "tracker-unwrap-test"
	tracker, _ := tcpPair(t, userMetadata(inbound, "alice", "10.2.2.3"), 0)
	defer tracker.Close()
	type unwrapper interface {
		UnwrapReader() (io.Reader, []N.CountFunc)
		UnwrapWriter() (io.Writer, []N.CountFunc)
	}
	u := tracker.(unwrapper)

	// no limit: the inner connection and a count function (splice possible)
	r, rc := u.UnwrapReader()
	assert.NotEqual(t, tracker, r)
	assert.Len(t, rc, 1)
	_, isCounter := r.(interface {
		UnwrapReader() (io.Reader, []N.CountFunc)
	})
	assert.False(t, isCounter)

	// a download limit: no splice, the copy reads through the tracker
	setLimit(t, statistic.UserLimit{Inbound: inbound, User: "alice", SpeedDown: 1_000_000})
	r, rc = u.UnwrapReader()
	assert.Empty(t, rc)
	_, isConn := r.(net.Conn)
	assert.False(t, isConn, "the reader must not be spliceable")
	w, wc := u.UnwrapWriter()
	assert.Len(t, wc, 1, "no upload limit: the writer is unwrapped")
	_ = w

	// a limit set while a splice runs is honoured by the count function
	start := time.Now()
	for _, f := range rc {
		f(1)
	}
	_, rc = (func() (io.Reader, []N.CountFunc) {
		statistic.DefaultManager.Users().DeleteLimit(statistic.UserKey{Inbound: inbound, User: "alice"})
		return u.UnwrapReader()
	})()
	require.Len(t, rc, 1)
	setLimit(t, statistic.UserLimit{Inbound: inbound, User: "alice", SpeedDown: 1_000_000})
	rc[0](600_000) // 600 ms at 1 MB/s minus the burst
	assert.InDelta(t, 0.5, time.Since(start).Seconds(), 0.1)
}

// TestTrackerQuotaClosesConnections checks that crossing the quota closes all
// the connections of the user.
func TestTrackerQuotaClosesConnections(t *testing.T) {
	const inbound = "tracker-quota-test"
	setLimit(t, statistic.UserLimit{Inbound: inbound, User: "alice", Quota: 1000})
	t1, r1 := tcpPair(t, userMetadata(inbound, "alice", "10.2.2.4"), 0)
	t2, _ := tcpPair(t, userMetadata(inbound, "alice", "10.2.2.4"), 0)
	other, _ := tcpPair(t, userMetadata(inbound, "bob", "10.2.2.4"), 0)
	defer other.Close()
	go func() { _, _ = io.Copy(io.Discard, r1) }()
	_, err := t1.Write(make([]byte, 1500))
	require.NoError(t, err)
	assert.Eventually(t, func() bool {
		return statistic.DefaultManager.Get(t1.(statistic.Tracker).ID()) == nil &&
			statistic.DefaultManager.Get(t2.(statistic.Tracker).ID()) == nil
	}, 2*time.Second, 10*time.Millisecond)
	assert.NotNil(t, statistic.DefaultManager.Get(other.(statistic.Tracker).ID()))

	_, err = statistic.DefaultManager.Admit(userMetadata(inbound, "alice", "10.2.2.4"))
	require.Error(t, err)
	statistic.DefaultManager.Users().ResetQuota(nil)
	adm, err := statistic.DefaultManager.Admit(userMetadata(inbound, "alice", "10.2.2.4"))
	require.NoError(t, err)
	adm.Release()
}

// TestTrackerQuotaStopsTransferAtOnce checks the quota stops a fast transfer
// in the read path itself, not only through the asynchronous close: a 5 MB
// download over a 300 KB quota must stop within about one copy buffer.
func TestTrackerQuotaStopsTransferAtOnce(t *testing.T) {
	// unique per run: the counters of DefaultManager outlive a test
	inbound := fmt.Sprintf("tracker-quota-stop-test-%d", time.Now().UnixNano())
	setLimit(t, statistic.UserLimit{Inbound: inbound, User: "carol", Quota: 300_000})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		relayThrough(t, inbound, "carol", 0, 5_000_000)
	}()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("the transfer did not stop at the quota")
	}
	s, ok := statistic.DefaultManager.Users().Get(statistic.UserKey{Inbound: inbound, User: "carol"})
	require.True(t, ok)
	assert.LessOrEqual(t, s.Up+s.Down, int64(300_000+256<<10), "overshoot past the quota is at most a buffer or two")
	assert.Less(t, s.Down, int64(5_000_000))
}

// TestTrackerReadWaiterUnderLimit checks that a user with a limit keeps the
// read waiter of a socket (no buffer while the remote is silent), and that
// the waiter counts what it reads.
func TestTrackerReadWaiterUnderLimit(t *testing.T) {
	inbound := fmt.Sprintf("tracker-read-waiter-test-%d", time.Now().UnixNano())
	setLimit(t, statistic.UserLimit{Inbound: inbound, User: "alice", SpeedDown: 1 << 30, Quota: 1 << 40})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	var tracker net.Conn = statistic.NewTCPTracker(outbound.NewConn(raw, outbound.NewDirect()), statistic.DefaultManager,
		userMetadata(inbound, "alice", "10.2.2.5"), nil, 0, 0, true)
	defer tracker.Close()
	remote := <-accepted
	require.NotNil(t, remote)
	defer remote.Close()

	r, rc := tracker.(interface {
		UnwrapReader() (io.Reader, []N.CountFunc)
	}).UnwrapReader()
	require.Empty(t, rc)
	_, ok := r.(interface{ CreateReadWaiter() (N.ReadWaiter, bool) })
	require.True(t, ok, "the limited reader offers a read waiter")
	waiter, ok := N.CreateReadWaiter(r)
	require.True(t, ok, "the socket under the tracker has a read waiter")
	waiter.InitializeReadWaiter(N.NewReadWaitOptions(r, nil))

	_, err = remote.Write(make([]byte, 1234))
	require.NoError(t, err)
	var got int
	for got < 1234 {
		buffer, err := waiter.WaitReadBuffer()
		require.NoError(t, err)
		got += buffer.Len()
		buffer.Release()
	}
	assert.Equal(t, int64(1234), userStat(t, inbound, "alice").Down)
	assert.Equal(t, int64(1234), tracker.(statistic.Tracker).Info().DownloadTotal.Load())
}

// TestTrackerQuotaResetKeepsNewConnections checks that the asynchronous pass
// closing the connections of a user over its quota, when it runs only after
// the quota was reset, leaves alone the connection the user opened since.
func TestTrackerQuotaResetKeepsNewConnections(t *testing.T) {
	inbound := fmt.Sprintf("tracker-quota-reset-test-%d", time.Now().UnixNano())
	um := statistic.DefaultManager.Users()
	closer := um.Closer()
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	um.SetCloser(func(k statistic.UserKey, still func() bool) {
		if k.Inbound != inbound {
			closer(k, still)
			return
		}
		once.Do(func() {
			close(started)
			<-release // hold the pass until the user reconnected
			closer(k, still)
			close(done)
		})
	})
	t.Cleanup(func() { um.SetCloser(closer) })
	setLimit(t, statistic.UserLimit{Inbound: inbound, User: "alice", Quota: 1000})

	old, r := tcpPair(t, userMetadata(inbound, "alice", "10.2.2.6"), 0)
	go func() { _, _ = io.Copy(io.Discard, r) }()
	_, err := old.Write(make([]byte, 1500))
	require.NoError(t, err)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("crossing the quota did not start closing the user")
	}

	um.ResetQuota(func(k statistic.UserKey) bool { return k.Inbound == inbound })
	adm, err := statistic.DefaultManager.Admit(userMetadata(inbound, "alice", "10.2.2.6"))
	require.NoError(t, err, "the reset admits the user again")
	adm.Release()
	fresh, _ := tcpPair(t, userMetadata(inbound, "alice", "10.2.2.6"), 0)
	defer fresh.Close()

	close(release)
	<-done
	assert.NotNil(t, statistic.DefaultManager.Get(fresh.(statistic.Tracker).ID()),
		"the connection opened after the reset survives the late close")
}

// UnwrapReader and UnwrapWriter hand out the same count functions on every
// call; a caller appending to them must not change what the next caller gets.
func TestTrackerUnwrapCountersShared(t *testing.T) {
	tracker, _ := tcpPair(t, userMetadata("tracker-unwrap-shared", "alice", "10.2.2.4"), 0)
	defer tracker.Close()
	u := tracker.(interface {
		UnwrapReader() (io.Reader, []N.CountFunc)
	})
	_, first := u.UnwrapReader()
	extra := false
	grown := append(first, func(int64) { extra = true })
	_, second := u.UnwrapReader()
	require.Len(t, second, 1)
	for _, f := range second {
		f(10)
	}
	assert.False(t, extra, "an append to one result must not show in the next")
	assert.Len(t, grown, 2)
	assert.Equal(t, int64(10), tracker.(statistic.Tracker).Info().DownloadTotal.Load())
}
