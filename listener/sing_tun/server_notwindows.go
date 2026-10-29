//go:build !windows

package sing_tun

import (
	"io"

	tun "github.com/metacubex/sing-tun"
)

func tunNew(options tun.Options) (tun.Tun, error) {
	return tun.New(options)
}

// startForwardingCheck only has work on Windows, see forwarding_check_windows.go
func startForwardingCheck(*Listener) io.Closer { return nil }
