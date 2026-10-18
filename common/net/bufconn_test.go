package net

import (
	"io"
	stdnet "net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBufferedConnLazyBuffer: no read buffer until a peek, and reads without
// one go straight to the conn.
func TestBufferedConnLazyBuffer(t *testing.T) {
	left, right := stdnet.Pipe()
	defer left.Close()
	defer right.Close()
	conn := NewBufferedConn(left)
	assert.Nil(t, conn.r)
	assert.Equal(t, 0, conn.Buffered())

	go right.Write([]byte("hello"))
	p := make([]byte, 5)
	_, err := io.ReadFull(conn, p)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(p))
	assert.Nil(t, conn.r, "a plain read allocates no buffer")

	go right.Write([]byte("world"))
	b, err := conn.Peek(5)
	require.NoError(t, err)
	assert.Equal(t, "world", string(b))
	assert.NotNil(t, conn.r)
	assert.True(t, conn.Peeked())
}

// TestBufferedConnDropsDrainedBuffer: the relay unwraps the conn once the
// buffer is drained (ReaderReplaceable), and the buffer goes with it; peeked
// data is never lost.
func TestBufferedConnDropsDrainedBuffer(t *testing.T) {
	left, right := stdnet.Pipe()
	defer left.Close()
	defer right.Close()
	conn := NewBufferedConn(left)

	go right.Write([]byte("abc"))
	_, err := conn.Peek(3)
	require.NoError(t, err)
	assert.False(t, conn.ReaderReplaceable(), "buffered data must be read first")
	assert.NotNil(t, conn.r)

	p := make([]byte, 3)
	_, err = io.ReadFull(conn, p)
	require.NoError(t, err)
	assert.Equal(t, "abc", string(p))
	assert.True(t, conn.ReaderReplaceable())
	assert.Nil(t, conn.r, "a drained buffer is dropped once the conn is unwrapped")

	// still usable: reads go to the conn, a peek takes a new buffer
	go right.Write([]byte("de"))
	b, err := conn.Peek(2)
	require.NoError(t, err)
	assert.Equal(t, "de", string(b))
	_, err = io.ReadFull(conn, p[:2])
	require.NoError(t, err)
	assert.Equal(t, "de", string(p[:2]))
}

// TestRelayDropsBufferedConnBuffer: a relayed BufferedConn that was peeked
// lets go of its buffer while the relay waits on it.
func TestRelayDropsBufferedConnBuffer(t *testing.T) {
	client, server := stdnet.Pipe()
	remote, remotePeer := stdnet.Pipe()
	defer client.Close()
	defer remotePeer.Close()
	conn := NewBufferedConn(server)

	go client.Write([]byte("first"))
	_, err := conn.Peek(1)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		Relay(conn, remote)
		close(done)
	}()
	p := make([]byte, 5)
	_, err = io.ReadFull(remotePeer, p)
	require.NoError(t, err)
	assert.Equal(t, "first", string(p))

	go client.Write([]byte("again"))
	_, err = io.ReadFull(remotePeer, p)
	require.NoError(t, err)
	assert.Equal(t, "again", string(p))

	client.Close()
	<-done
	assert.Nil(t, conn.r)
}
