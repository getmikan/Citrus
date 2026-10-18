package tuic

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	v5 "github.com/metacubex/mihomo/transport/tuic/v5"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The read buffer of a TCP relay stream holds the longest CONNECT command
// (a 255-byte domain), and the data the client sent right after it reaches
// the relay.
func TestStreamHeaderBuffer(t *testing.T) {
	host := strings.Repeat("a", 251) + ".com" // 255 bytes, the longest
	var b bytes.Buffer
	require.NoError(t, v5.NewConnect(v5.NewAddress(&C.Metadata{Host: host, DstPort: 443})).WriteTo(&b))
	payload := bytes.Repeat([]byte("p"), 3*streamHeaderBufferSize)
	b.Write(payload)

	left, right := net.Pipe()
	defer left.Close()
	go func() {
		_, _ = right.Write(b.Bytes())
		_ = right.Close()
	}()

	conn := N.NewBufferedConnSize(left, streamHeaderBufferSize)
	ver, err := conn.Peek(1)
	require.NoError(t, err)
	assert.Equal(t, byte(v5.VER), ver[0])
	connect, err := v5.ReadConnect(conn)
	require.NoError(t, err)
	assert.Equal(t, host, string(connect.ADDR.ADDR[1:]))

	var rest []byte
	if cached := conn.ReadCached(); cached != nil {
		rest = append(rest, cached.Bytes()...)
		cached.Release()
	}
	tail, err := io.ReadAll(conn)
	require.NoError(t, err)
	assert.Equal(t, payload, append(rest, tail...))
}
