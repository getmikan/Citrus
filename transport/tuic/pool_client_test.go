package tuic

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/quic-go"
	"github.com/stretchr/testify/assert"
)

func TestPoolClientClose(t *testing.T) {
	var dials atomic.Int32
	dialErr := errors.New("dial failed")
	pool := NewPoolClientV5(&ClientOptionV5{MaxOpenStreams: 10}, func(ctx context.Context) (*quic.Conn, error) {
		dials.Add(1)
		return nil, dialErr
	})
	metadata := &C.Metadata{Host: "example.com", DstPort: 443}

	// a first dial puts a client into the pool, the dial itself fails
	_, err := pool.DialContext(context.Background(), metadata)
	assert.ErrorIs(t, err, dialErr)
	_, err = pool.ListenPacket(context.Background(), metadata)
	assert.ErrorIs(t, err, dialErr)
	assert.Equal(t, int32(2), dials.Load())
	assert.Equal(t, 1, pool.tcpClients.Len())
	assert.Equal(t, 1, pool.udpClients.Len())
	pooled := pool.tcpClients.Front().Value

	assert.NoError(t, pool.Close())
	assert.Equal(t, 0, pool.tcpClients.Len())
	assert.Equal(t, 0, pool.udpClients.Len())

	// after Close nothing is dialed: neither through the pool nor through a
	// client somebody still holds
	_, err = pool.DialContext(context.Background(), metadata)
	assert.ErrorIs(t, err, ClientClosed)
	_, err = pool.ListenPacket(context.Background(), metadata)
	assert.ErrorIs(t, err, ClientClosed)
	_, err = pooled.DialContext(context.Background(), metadata)
	assert.ErrorIs(t, err, ClientClosed)
	assert.Equal(t, int32(2), dials.Load())
	assert.Equal(t, 0, pool.tcpClients.Len())
	assert.Equal(t, 0, pool.udpClients.Len())

	// a second Close is harmless
	assert.NoError(t, pool.Close())
}
