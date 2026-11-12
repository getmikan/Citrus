package fanin

import (
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func listenN(t *testing.T, n int) []net.PacketConn {
	t.Helper()
	conns := make([]net.PacketConn, 0, n)
	for range n {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		conns = append(conns, pc)
	}
	return conns
}

func readPacket(t *testing.T, pc net.PacketConn) (string, net.Addr) {
	t.Helper()
	require.NoError(t, pc.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 2048)
	n, addr, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	return string(buf[:n]), addr
}

// waitGoroutines waits for the number of goroutines to drop to at most n.
func waitGoroutines(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > n {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("%d goroutines, want at most %d:\n%s", runtime.NumGoroutine(), n, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestReadsEverySocket(t *testing.T) {
	sockets := listenN(t, 3)
	conn := New(sockets)
	defer conn.Close()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer client.Close()

	for i, s := range sockets {
		msg := strings.Repeat("x", i+1)
		_, err := client.WriteTo([]byte(msg), s.LocalAddr())
		require.NoError(t, err)
		got, from := readPacket(t, conn)
		assert.Equal(t, msg, got)
		assert.Equal(t, client.LocalAddr().String(), from.String())
	}
}

func TestWriteToRepliesFromLastSocket(t *testing.T) {
	sockets := listenN(t, 3)
	conn := New(sockets)
	defer conn.Close()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer client.Close()

	// an unknown destination is served from the first socket
	other, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer other.Close()
	_, err = conn.WriteTo([]byte("first"), other.LocalAddr())
	require.NoError(t, err)
	_, from := readPacket(t, other)
	assert.Equal(t, sockets[0].LocalAddr().String(), from.String())

	for _, i := range []int{2, 1, 2, 0} {
		_, err := client.WriteTo([]byte("ping"), sockets[i].LocalAddr())
		require.NoError(t, err)
		_, peer := readPacket(t, conn)
		_, err = conn.WriteTo([]byte("pong"), peer)
		require.NoError(t, err)
		got, from := readPacket(t, client)
		assert.Equal(t, "pong", got)
		assert.Equal(t, sockets[i].LocalAddr().String(), from.String(), "reply after a packet to socket %d", i)
	}
}

func TestReadDeadlineWakesReadFrom(t *testing.T) {
	conn := New(listenN(t, 2))
	defer conn.Close()

	// a deadline in the future expires
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, _, err := conn.ReadFrom(make([]byte, 10))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	var nErr net.Error
	require.True(t, errors.As(err, &nErr))
	assert.True(t, nErr.Timeout())

	// a deadline set in the past wakes a blocked ReadFrom (quic-go stops
	// reading this way)
	require.NoError(t, conn.SetReadDeadline(time.Time{}))
	errCh := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadFrom(make([]byte, 10))
		errCh <- err
	}()
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-errCh:
		t.Fatalf("ReadFrom returned early: %v", err)
	default:
	}
	require.NoError(t, conn.SetReadDeadline(time.Now()))
	select {
	case err := <-errCh:
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(5 * time.Second):
		t.Fatal("SetReadDeadline did not wake ReadFrom")
	}

	// clearing the deadline makes the conn readable again
	require.NoError(t, conn.SetReadDeadline(time.Time{}))
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer client.Close()
	_, err = client.WriteTo([]byte("again"), conn.LocalAddr())
	require.NoError(t, err)
	got, _ := readPacket(t, conn)
	assert.Equal(t, "again", got)
}

func TestCloseWakesReadFromAndLeaksNothing(t *testing.T) {
	before := runtime.NumGoroutine()
	conn := New(listenN(t, 50))

	// fill the queue, so readers block on it too
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer client.Close()
	for range 2 * queueSize {
		_, _ = client.WriteTo([]byte("x"), conn.LocalAddr())
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 10)
		for {
			if _, _, err := conn.ReadFrom(buf); err != nil {
				assert.ErrorIs(t, err, net.ErrClosed)
				return
			}
		}
	}()
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, conn.Close())
	require.NoError(t, conn.Close(), "a second Close")
	wg.Wait()
	_, err = conn.WriteTo([]byte("x"), client.LocalAddr())
	assert.ErrorIs(t, err, net.ErrClosed)
	waitGoroutines(t, before)
}

func TestSocketOptionsReachEverySocket(t *testing.T) {
	sockets := listenN(t, 3)
	conn := New(sockets)
	defer conn.Close()

	require.NoError(t, conn.(interface{ SetReadBuffer(int) error }).SetReadBuffer(1<<20))
	require.NoError(t, conn.(interface{ SetWriteBuffer(int) error }).SetWriteBuffer(1<<20))

	sc, ok := conn.(syscall.Conn)
	require.True(t, ok, "UDP sockets give a SyscallConn")
	raw, err := sc.SyscallConn()
	require.NoError(t, err)
	var fds []uintptr
	require.NoError(t, raw.Control(func(fd uintptr) { fds = append(fds, fd) }))
	assert.Len(t, fds, len(sockets))
	for i, s := range sockets {
		sRaw, err := s.(syscall.Conn).SyscallConn()
		require.NoError(t, err)
		require.NoError(t, sRaw.Control(func(fd uintptr) { assert.Equal(t, fd, fds[i]) }))
	}
}

func TestLocalAddrs(t *testing.T) {
	sockets := listenN(t, 3)
	conn := New(sockets)
	defer conn.Close()
	addrs := LocalAddrs(conn)
	require.Len(t, addrs, 3)
	for i, s := range sockets {
		assert.Equal(t, s.LocalAddr(), addrs[i])
	}

	plain := listenN(t, 1)[0]
	defer plain.Close()
	assert.Equal(t, []net.Addr{plain.LocalAddr()}, LocalAddrs(plain))
	assert.Nil(t, Of(plain))
}

type netListener struct{}

func (netListener) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, network, address)
}

// freePorts returns n free UDP ports on 127.0.0.1 (not consecutive).
func freePorts(t *testing.T, n int) []string {
	t.Helper()
	var ports []string
	for _, pc := range listenN(t, n) {
		_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
		ports = append(ports, port)
		_ = pc.Close()
	}
	return ports
}

func TestListenGroupsByHost(t *testing.T) {
	ports := freePorts(t, 4)
	listen := strings.Join([]string{
		"127.0.0.1:" + ports[0], "127.0.0.1:" + ports[1], "127.0.0.1:" + ports[2],
	}, ",")

	var prepared int
	conns, err := Listen(context.Background(), netListener{}, listen, func(net.PacketConn) { prepared++ })
	require.NoError(t, err)
	require.Len(t, conns, 1, "the ports of one host share a conn")
	assert.Equal(t, 3, prepared)
	assert.NotNil(t, Of(conns[0]))
	assert.Len(t, LocalAddrs(conns[0]), 3)
	require.NoError(t, conns[0].Close())

	// a single port keeps the plain socket (and quic-go its OOB path)
	conns, err = Listen(context.Background(), netListener{}, "127.0.0.1:"+ports[3], nil)
	require.NoError(t, err)
	require.Len(t, conns, 1)
	_, ok := conns[0].(*net.UDPConn)
	assert.True(t, ok, "a single port is a *net.UDPConn, got %T", conns[0])
	require.NoError(t, conns[0].Close())

	// different hosts stay apart
	conns, err = Listen(context.Background(), netListener{}, "127.0.0.1:"+ports[0]+",127.0.0.1:"+ports[1]+",[::1]:"+ports[2], nil)
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	require.Len(t, conns, 2)
	assert.NotNil(t, Of(conns[0]))
	assert.Nil(t, Of(conns[1]))
	for _, c := range conns {
		require.NoError(t, c.Close())
	}
}

func TestListenEachKeepsSockets(t *testing.T) {
	ports := freePorts(t, 2)
	conns, err := ListenEach(context.Background(), netListener{}, "127.0.0.1:"+ports[0]+",127.0.0.1:"+ports[1], nil)
	require.NoError(t, err)
	require.Len(t, conns, 2)
	for _, c := range conns {
		_, ok := c.(*net.UDPConn)
		assert.True(t, ok, "got %T", c)
		require.NoError(t, c.Close())
	}
}

func TestListenClosesOnError(t *testing.T) {
	busy, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer busy.Close()
	ports := freePorts(t, 1)

	var opened []net.PacketConn
	_, err = Listen(context.Background(), netListener{}, "127.0.0.1:"+ports[0]+","+busy.LocalAddr().String(), func(pc net.PacketConn) {
		opened = append(opened, pc)
	})
	require.Error(t, err)
	require.Len(t, opened, 1)
	_, err = opened[0].WriteTo([]byte("x"), busy.LocalAddr())
	assert.ErrorIs(t, err, net.ErrClosed, "the socket opened before the error is closed")
}

// TestGoroutinesPerPort checks an idle range costs one goroutine per port.
func TestGoroutinesPerPort(t *testing.T) {
	if testing.Short() {
		t.Skip("opens 1000 sockets")
	}
	const n = 1000
	before := runtime.NumGoroutine()
	conn := New(listenN(t, n))
	time.Sleep(100 * time.Millisecond)
	during := runtime.NumGoroutine() - before
	t.Logf("%d sockets: %d goroutines", n, during)
	assert.LessOrEqual(t, during, n+5)
	require.NoError(t, conn.Close())
	waitGoroutines(t, before)
}
