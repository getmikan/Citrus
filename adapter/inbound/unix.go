package inbound

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/metacubex/mihomo/log"
)

// UnixSocketPrefix marks a listen address as the path of a unix socket, as in
// "listen: unix:/run/citrus/vless.sock".
const UnixSocketPrefix = "unix:"

// DefaultUnixSocketMode lets the user the core runs as and its group connect
// to a listener's unix socket: put the reverse proxy's user (www-data, caddy)
// in that group, or set a looser mode.
const DefaultUnixSocketMode fs.FileMode = 0o660

// staleSocketDialTimeout bounds the probe that tells a live socket from one a
// crashed process left behind.
const staleSocketDialTimeout = time.Second

// UnixPeerAddr is the address a connection that came over a unix socket
// reports for both of its ends. A unix peer has no IP: it is a process on this
// host, in practice the reverse proxy in front of the listener, so it is
// reported as loopback, the same as a proxy that reaches a 127.0.0.1 port.
// Everything that keys on the source IP (lan-allowed-ips, skip-auth-prefixes,
// trusted-proxies, per-user IP limits, auth events, SRC-IP rules) sees
// 127.0.0.1. The port is 0: there is no port, and a made-up one could match an
// unrelated local socket in a process lookup.
func UnixPeerAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 0}
}

// UnixListenAddr is the net.Addr of a unix socket listener. It prints as the
// listen address of the config, "unix:/path".
type UnixListenAddr string

func (a UnixListenAddr) Network() string { return "unix" }
func (a UnixListenAddr) String() string  { return UnixSocketPrefix + string(a) }

// ListenUnix listens on a unix stream socket at path whose permissions are
// mode (ignored on Windows, where the ACL of the directory governs access).
//
// A socket file left at path by a process that is gone is removed first; a
// socket somebody still listens on, and anything that is not a socket, is
// never touched and makes ListenUnix fail. The socket is created with its
// final permissions before anybody can connect to it, and Close removes it
// unless another listener has taken the path over since.
//
// The accepted connections report UnixPeerAddr for both of their ends.
func ListenUnix(ctx context.Context, path string, mode fs.FileMode) (net.Listener, error) {
	if dir := filepath.Dir(path); dir != "" {
		if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, err
			}
		}
	}
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	l, err := listenUnixSocket(ctx, path, mode)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	return &unixListener{Listener: l, path: path, info: info}, nil
}

// removeStaleSocket clears path for a new socket: it does nothing when there
// is no file, removes a socket nobody listens on and refuses everything else.
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("unix socket %s: the path exists and is not a socket, refusing to replace it", path)
	}
	conn, err := net.DialTimeout("unix", path, staleSocketDialTimeout)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("unix socket %s: already in use by another process", path)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("unix socket %s: a listener holds it but does not accept: %w", path, err)
	}
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("unix socket %s: %w", path, err)
	}
	// connection refused: the socket was left behind by a process that is gone
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("unix socket %s: remove stale socket: %w", path, err)
	}
	log.Infoln("Removed stale unix socket %s", path)
	return nil
}

// bindUnix binds a unix stream socket at path. The socket file belongs to the
// caller: closing the listener never removes it.
func bindUnix(ctx context.Context, path string) (net.Listener, error) {
	l, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	if ul, ok := l.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	return l, nil
}

type unixListener struct {
	net.Listener
	path string
	info os.FileInfo
}

func (l *unixListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if uc, ok := c.(*net.UnixConn); ok {
		return &unixConn{UnixConn: uc}, nil
	}
	return c, nil
}

func (l *unixListener) Addr() net.Addr {
	return UnixListenAddr(l.path)
}

func (l *unixListener) Close() error {
	err := l.Listener.Close()
	// remove the socket file only while it is still ours
	if info, statErr := os.Lstat(l.path); statErr == nil && os.SameFile(info, l.info) {
		_ = os.Remove(l.path)
	}
	return err
}

// unixConn is a connection accepted on a unix socket. It keeps the methods of
// *net.UnixConn (ReadFrom, WriteTo, CloseWrite, SyscallConn) and reports
// UnixPeerAddr for both ends, so code that parses an IP out of an address
// works unchanged.
type unixConn struct {
	*net.UnixConn
}

func (c *unixConn) RemoteAddr() net.Addr { return UnixPeerAddr() }
func (c *unixConn) LocalAddr() net.Addr  { return UnixPeerAddr() }
