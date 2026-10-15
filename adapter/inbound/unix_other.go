//go:build !windows

package inbound

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"

	"github.com/metacubex/mihomo/log"
)

// listenUnixSocket binds a unix socket at path with permissions mode.
//
// The socket is bound inside a fresh 0700 directory next to path, gets its
// final permissions there and is then linked into place, so nobody can
// connect to it with looser permissions than mode, and an existing file at
// path (created since removeStaleSocket looked) is never replaced. A
// filesystem without hard links gets a rename instead.
func listenUnixSocket(ctx context.Context, path string, mode fs.FileMode) (net.Listener, error) {
	l, err := listenUnixPrivate(ctx, path, mode)
	if err == nil {
		return l, nil
	}
	if errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("unix socket %s: %w", path, err)
	}
	// e.g. the temporary path exceeds the sun_path limit: bind in place and
	// tighten at once; the umask keeps the socket closed to others until then
	log.Warnln("Unix socket %s: private bind failed, binding in place: %s", path, err)
	l, err = bindUnix(ctx, path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, mode); err != nil {
		_ = l.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return l, nil
}

func listenUnixPrivate(ctx context.Context, path string, mode fs.FileMode) (net.Listener, error) {
	tmpDir, err := os.MkdirTemp(filepath.Dir(path), ".citrus-sock-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)
	tmpPath := filepath.Join(tmpDir, "s")

	l, err := bindUnix(ctx, tmpPath)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(tmpPath, mode); err != nil {
		_ = l.Close()
		return nil, err
	}
	if err = os.Link(tmpPath, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			_ = l.Close()
			return nil, err
		}
		if err = os.Rename(tmpPath, path); err != nil {
			_ = l.Close()
			return nil, err
		}
	}
	return l, nil
}
