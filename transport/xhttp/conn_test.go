package xhttp

import (
	"errors"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newPipeTestConn() (*Conn, *io.PipeReader, *io.PipeWriter, *atomic.Int32) {
	upR, upW := io.Pipe()     // conn writes go to upR
	downR, downW := io.Pipe() // downW feeds conn reads
	var closes atomic.Int32
	conn := &Conn{writer: upW, reader: downR, onClose: func() { closes.Add(1) }}
	return conn, upR, downW, &closes
}

// A write deadline that passes while the conn is idle must not close it: yamux sets one
// ahead of its writes and leaves it in place between them.
func TestConnIdleDeadlineKeepsConnOpen(t *testing.T) {
	conn, upR, downW, closes := newPipeTestConn()
	defer conn.Close()

	require.NoError(t, conn.SetWriteDeadline(time.Now().Add(20*time.Millisecond)))
	time.Sleep(60 * time.Millisecond)
	assert.Equal(t, int32(0), closes.Load(), "an idle conn was closed by its deadline")

	_, err := conn.Write([]byte("x"))
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded)

	require.NoError(t, conn.SetWriteDeadline(time.Now().Add(time.Minute)))
	go func() { _, _ = io.ReadFull(upR, make([]byte, 2)) }()
	_, err = conn.Write([]byte("ok"))
	assert.NoError(t, err)

	go func() { _, _ = downW.Write([]byte("hi")) }()
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	assert.NoError(t, err)
	assert.Equal(t, "hi", string(buf))
}

// A read still blocked when its deadline passes is ended with a timeout.
func TestConnBlockedReadDeadline(t *testing.T) {
	conn, _, _, closes := newPipeTestConn()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
	start := time.Now()
	_, err := conn.Read(make([]byte, 1))
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
	var ne interface{ Timeout() bool }
	assert.True(t, errors.As(err, &ne) && ne.Timeout())
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.Equal(t, int32(1), closes.Load())
}

// A deadline cleared or moved before it passes has no effect.
func TestConnDeadlineReset(t *testing.T) {
	conn, _, downW, closes := newPipeTestConn()
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Millisecond)))
	require.NoError(t, conn.SetDeadline(time.Time{}))
	go func() {
		time.Sleep(60 * time.Millisecond)
		_, _ = downW.Write([]byte("z"))
	}()
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, int32(0), closes.Load())
}

func TestConnCloseOnce(t *testing.T) {
	conn, _, _, closes := newPipeTestConn()
	require.NoError(t, conn.SetReadDeadline(time.Now()))
	_ = conn.Close()
	_ = conn.Close()
	assert.Equal(t, int32(1), closes.Load())
}
