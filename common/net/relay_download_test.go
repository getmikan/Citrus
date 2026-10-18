package net

import (
	"bytes"
	"sync"
	"testing"

	"github.com/metacubex/sing/common/buf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sizeWriter is a destination that is not a socket and records the size of
// every write.
type sizeWriter struct {
	mu    sync.Mutex
	data  bytes.Buffer
	sizes []int
}

func (w *sizeWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sizes = append(w.sizes, len(b))
	return w.data.Write(b)
}

// TestCopyConnFromSocketGrowsReads copies a socket to a destination that is
// not one (the download of a proxied connection): the first reads use pool
// buffers, and once one is filled the copy reads largeReadSize at a time.
func TestCopyConnFromSocketGrowsReads(t *testing.T) {
	src, peer := tcpPair(t)
	data := randomBytes(t, 16<<20+321)
	sent := make(chan error, 1)
	go func() {
		_, err := peer.Write(data)
		if err == nil {
			err = peer.CloseWrite()
		}
		sent <- err
	}()
	dst := &sizeWriter{}
	n, err := copyConn(dst, src)
	require.NoError(t, err)
	require.NoError(t, <-sent)
	assert.Equal(t, int64(len(data)), n)
	assert.True(t, bytes.Equal(data, dst.data.Bytes()), "data differs")

	grown := -1
	for i, size := range dst.sizes {
		require.LessOrEqual(t, size, largeReadSize, "write #%d", i)
		if size > buf.BufferSize && grown == -1 {
			grown = i
		}
	}
	assert.NotEqual(t, -1, grown, "no read of more than %d bytes in %d writes", buf.BufferSize, len(dst.sizes))
}

// TestCopyConnFromSocketShortReads keeps the pool buffer while no read fills
// it.
func TestCopyConnFromSocketShortReads(t *testing.T) {
	src, peer := tcpPair(t)
	dst := &sizeWriter{}
	done := make(chan struct{})
	go func() {
		_, _ = copyConn(dst, src)
		close(done)
	}()
	for i := 0; i < 20; i++ {
		_, err := peer.Write(bytes.Repeat([]byte{byte(i)}, 1000))
		require.NoError(t, err)
	}
	require.NoError(t, peer.CloseWrite())
	<-done
	for i, size := range dst.sizes {
		assert.LessOrEqual(t, size, buf.BufferSize, "write #%d", i)
	}
	assert.Equal(t, 20000, dst.data.Len())
}
