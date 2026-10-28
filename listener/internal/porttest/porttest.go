// Package porttest has the helpers of the tests that check a failed listener
// gives its ports back.
package porttest

import (
	"math/rand/v2"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// FreeAddr returns a loopback address whose port was free a moment ago, for
// TCP and UDP. The port is below the ephemeral range, so that the ":0"
// listeners of the tests running in parallel do not take it first, and a
// BusyAddr port is always higher.
func FreeAddr(t *testing.T) string {
	t.Helper()
	for range 100 {
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(20000+rand.IntN(20000)))
		if free(addr, "tcp") && free(addr, "udp") {
			return addr
		}
	}
	t.Fatal("no free port")
	return ""
}

// BusyAddr returns a loopback address held on network until the test ends.
func BusyAddr(t *testing.T, network string) string {
	t.Helper()
	addr, closeFn := listen(t, network, "127.0.0.1:0")
	t.Cleanup(func() { _ = closeFn() })
	return addr
}

// RequireFree fails the test unless addr can be listened on again. It waits a
// little: on Windows a closed socket keeps its port until the goroutine
// blocked in its accept or read has returned.
func RequireFree(t *testing.T, network, addr string) {
	t.Helper()
	var err error
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		var closeFn func() error
		if _, closeFn, err = tryListen(network, addr); err == nil {
			_ = closeFn()
			return
		}
		if time.Now().After(deadline) {
			break
		}
	}
	require.NoError(t, err, "the failed listener keeps %s/%s", addr, network)
}

func free(addr, network string) bool {
	_, closeFn, err := tryListen(network, addr)
	if err != nil {
		return false
	}
	_ = closeFn()
	return true
}

func listen(t *testing.T, network, addr string) (string, func() error) {
	t.Helper()
	addr, closeFn, err := tryListen(network, addr)
	require.NoError(t, err)
	return addr, closeFn
}

func tryListen(network, addr string) (string, func() error, error) {
	if network == "udp" {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return "", nil, err
		}
		return pc.LocalAddr().String(), pc.Close, nil
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, err
	}
	return l.Addr().String(), l.Close, nil
}
