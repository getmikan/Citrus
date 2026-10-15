package inbound

import (
	"context"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func unixTestPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cs")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

func TestListenUnix_PeerIsLoopback(t *testing.T) {
	path := unixTestPath(t, "peer.sock")
	l, err := ListenUnix(context.Background(), path, DefaultUnixSocketMode)
	require.NoError(t, err)
	defer l.Close()
	assert.Equal(t, "unix:"+path, l.Addr().String())
	assert.Equal(t, "unix", l.Addr().Network())

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
		close(accepted)
	}()
	client, err := net.Dial("unix", path)
	require.NoError(t, err)
	defer client.Close()
	c := <-accepted
	require.NotNil(t, c)
	defer c.Close()

	for _, addr := range []net.Addr{c.RemoteAddr(), c.LocalAddr()} {
		tcpAddr, ok := addr.(*net.TCPAddr)
		require.True(t, ok, "%T", addr)
		assert.Equal(t, netip.MustParseAddrPort("127.0.0.1:0"), tcpAddr.AddrPort())
	}
	// the source IP checks see a loopback peer
	SetAllowedIPs([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	SetSkipAuthPrefixes([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	defer SetAllowedIPs(nil)
	defer SetSkipAuthPrefixes(nil)
	assert.True(t, IsRemoteAddrDisAllowed(c.RemoteAddr()))
	assert.False(t, SkipAuthRemoteAddr(c.RemoteAddr()))

	// the connection still carries data both ways
	_, err = client.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = c.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf))
}

func TestListenUnix_Mode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ignores the unix permission bits")
	}
	for _, mode := range []fs.FileMode{DefaultUnixSocketMode, 0o600, 0o666} {
		path := unixTestPath(t, "mode.sock")
		l, err := ListenUnix(context.Background(), path, mode)
		require.NoError(t, err)
		info, err := os.Lstat(path)
		require.NoError(t, err)
		assert.Equal(t, fs.ModeSocket, info.Mode().Type())
		assert.Equal(t, mode, info.Mode().Perm())
		// the private directory the socket was bound in is gone
		entries, err := os.ReadDir(filepath.Dir(path))
		require.NoError(t, err)
		assert.Len(t, entries, 1)
		require.NoError(t, l.Close())
		assert.NoFileExists(t, path)
	}
}

func TestListenUnix_StaleSocket(t *testing.T) {
	path := unixTestPath(t, "stale.sock")
	stale, err := net.Listen("unix", path)
	require.NoError(t, err)
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	require.NoError(t, stale.Close())
	require.FileExists(t, path)

	l, err := ListenUnix(context.Background(), path, DefaultUnixSocketMode)
	require.NoError(t, err)
	c, err := net.Dial("unix", path)
	require.NoError(t, err)
	_ = c.Close()
	require.NoError(t, l.Close())
	assert.NoFileExists(t, path)
}

func TestListenUnix_RefusesRegularFile(t *testing.T) {
	path := unixTestPath(t, "file")
	require.NoError(t, os.WriteFile(path, []byte("keep me"), 0o600))
	_, err := ListenUnix(context.Background(), path, DefaultUnixSocketMode)
	require.ErrorContains(t, err, "not a socket")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "keep me", string(data))

	dir := unixTestPath(t, "dir")
	require.NoError(t, os.Mkdir(dir, 0o700))
	_, err = ListenUnix(context.Background(), dir, DefaultUnixSocketMode)
	require.ErrorContains(t, err, "not a socket")
	assert.DirExists(t, dir)
}

func TestListenUnix_InUse(t *testing.T) {
	path := unixTestPath(t, "busy.sock")
	first, err := ListenUnix(context.Background(), path, DefaultUnixSocketMode)
	require.NoError(t, err)
	defer first.Close()
	go func() {
		for {
			c, err := first.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, err = ListenUnix(context.Background(), path, DefaultUnixSocketMode)
	require.ErrorContains(t, err, "already in use")
	c, err := net.Dial("unix", path)
	require.NoError(t, err)
	_ = c.Close()
}

// TestListenUnix_CloseKeepsSuccessor: a listener closed after another one
// took its path over leaves the new socket alone.
func TestListenUnix_CloseKeepsSuccessor(t *testing.T) {
	path := unixTestPath(t, "handover.sock")
	old, err := ListenUnix(context.Background(), path, DefaultUnixSocketMode)
	require.NoError(t, err)
	require.NoError(t, os.Remove(path))
	successor, err := ListenUnix(context.Background(), path, DefaultUnixSocketMode)
	require.NoError(t, err)
	defer successor.Close()

	require.NoError(t, old.Close())
	require.FileExists(t, path)
	c, err := net.Dial("unix", path)
	require.NoError(t, err)
	_ = c.Close()
}

func TestListenUnix_CreatesDirectory(t *testing.T) {
	path := filepath.Join(unixTestPath(t, "sub"), "s.sock")
	l, err := ListenUnix(context.Background(), path, DefaultUnixSocketMode)
	require.NoError(t, err)
	require.NoError(t, l.Close())
}
