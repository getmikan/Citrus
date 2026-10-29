package accept

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type temporaryError struct{}

func (temporaryError) Error() string   { return "temporary accept failure" }
func (temporaryError) Timeout() bool   { return false }
func (temporaryError) Temporary() bool { return true }

// fakeListener returns errs in order, then the connections of conns, then
// net.ErrClosed once conns is closed.
type fakeListener struct {
	mu    sync.Mutex
	errs  []error
	calls int
	conns chan net.Conn
}

func (l *fakeListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.calls++
	if len(l.errs) > 0 {
		err := l.errs[0]
		l.errs = l.errs[1:]
		l.mu.Unlock()
		return nil, err
	}
	l.mu.Unlock()
	c, ok := <-l.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}
func (l *fakeListener) Close() error   { return nil }
func (l *fakeListener) Addr() net.Addr { return &net.TCPAddr{} }

// An accept error that is not net.ErrClosed (EMFILE, or on Windows
// WSAENOBUFS, which is not Temporary) must neither end the loop nor make it
// spin.
func TestNextBacksOffOnErrors(t *testing.T) {
	failures := []error{temporaryError{}, errors.New("WSAENOBUFS"), temporaryError{}, temporaryError{}}
	l := &fakeListener{errs: failures, conns: make(chan net.Conn, 1)}
	want, peer := net.Pipe()
	defer want.Close()
	defer peer.Close()
	l.conns <- want
	start := time.Now()
	c, err := Next(l, func() bool { return false })
	require.NoError(t, err)
	require.Equal(t, want, c)
	require.Equal(t, len(failures)+1, l.calls)
	// 5+10+20+40ms
	require.GreaterOrEqual(t, time.Since(start), 75*time.Millisecond, "no back-off between failed accepts")
}

func TestNextReturnsOnClose(t *testing.T) {
	l := &fakeListener{errs: []error{&net.OpError{Op: "accept", Err: net.ErrClosed}}}
	_, err := Next(l, func() bool { return false })
	require.ErrorIs(t, err, net.ErrClosed)
	require.Equal(t, 1, l.calls, "a closed listener must end the loop, not be retried")
}

// A failed handshake listener keeps returning its own error after Close.
func TestNextReturnsOnceClosed(t *testing.T) {
	failed := errors.New("handshake listener failed")
	l := &fakeListener{errs: []error{failed, failed}}
	_, err := Next(l, func() bool { return true })
	require.ErrorIs(t, err, failed)
	require.Equal(t, 1, l.calls)
}
