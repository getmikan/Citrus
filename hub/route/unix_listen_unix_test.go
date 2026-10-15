//go:build !windows

package route

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestListenUnixMode(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want os.FileMode
	}{
		{"", 0o600},
		{"0660", 0o660},
	} {
		t.Run("mode="+tc.env, func(t *testing.T) {
			t.Setenv(UnixSocketModeEnv, tc.env)
			dir := shortTempDir(t)
			addr := filepath.Join(dir, "c.sock")
			l, err := listenUnix(addr)
			if err != nil {
				t.Fatalf("listenUnix: %v", err)
			}

			info, err := os.Lstat(addr)
			if err != nil {
				t.Fatalf("stat socket: %v", err)
			}
			if info.Mode()&os.ModeSocket == 0 {
				t.Errorf("%s is not a socket: %v", addr, info.Mode())
			}
			if got := info.Mode().Perm(); got != tc.want {
				t.Errorf("socket mode = %#o, want %#o", got, tc.want)
			}
			if got := l.Addr().String(); got != addr {
				t.Errorf("Addr() = %q, want %q", got, addr)
			}

			// the private bind directory must not be left behind
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Errorf("unexpected entries next to the socket: %v", entries)
			}

			c, err := net.Dial("unix", addr)
			if err != nil {
				t.Fatalf("dial as owner: %v", err)
			}
			_ = c.Close()

			if err = l.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}
			if _, err = os.Lstat(addr); !os.IsNotExist(err) {
				t.Errorf("socket file left after close: %v", err)
			}
		})
	}
}

func TestListenUnixReplacesStaleSocket(t *testing.T) {
	addr := filepath.Join(shortTempDir(t), "c.sock")
	if err := os.WriteFile(addr, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	l, err := listenUnix(addr)
	if err != nil {
		t.Fatalf("listenUnix: %v", err)
	}
	defer l.Close()
	info, err := os.Lstat(addr)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Errorf("socket mode = %v, want socket 0600", info.Mode())
	}
}
