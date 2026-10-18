package net

import (
	"io"
	stdnet "net"
	"testing"

	"github.com/metacubex/mihomo/common/buf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newPipeBufferedConn(t *testing.T, data string) *BufferedConn {
	left, right := stdnet.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	go func() {
		_, _ = right.Write([]byte(data))
		_ = right.Close()
	}()
	return NewBufferedConn(left)
}

// A connection that is only relayed never gets a bufio.Reader.
func TestBufferedConnLazyReader(t *testing.T) {
	c := newPipeBufferedConn(t, "hello")
	assert.Equal(t, 0, c.Buffered())
	assert.Nil(t, c.ReadCached())
	assert.True(t, c.ReaderReplaceable())

	b := buf.NewSize(16)
	defer b.Release()
	require.NoError(t, c.ReadBuffer(b))
	assert.Equal(t, "hello", string(b.Bytes()))
	assert.Nil(t, c.r, "no reader without Peek or Read")
}

func TestBufferedConnPeekThenRelay(t *testing.T) {
	c := newPipeBufferedConn(t, "hello")
	p, err := c.Peek(2)
	require.NoError(t, err)
	assert.Equal(t, "he", string(p))
	assert.True(t, c.Peeked())
	assert.False(t, c.ReaderReplaceable())

	cached := c.ReadCached()
	require.NotNil(t, cached)
	data := string(cached.Bytes())
	cached.Release()
	rest, err := io.ReadAll(c) // after ReadCached dropped the reader
	require.NoError(t, err)
	assert.Equal(t, "hello", data+string(rest))
}

func TestBufferedConnRead(t *testing.T) {
	c := newPipeBufferedConn(t, "hello")
	b, err := c.ReadByte()
	require.NoError(t, err)
	assert.Equal(t, byte('h'), b)
	require.NoError(t, c.UnreadByte())
	data, err := io.ReadAll(c)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(data))
}
