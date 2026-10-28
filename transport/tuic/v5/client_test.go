package v5

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/tuic/types"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

// sinkServer accepts QUIC connections and reads their streams to the end,
// without speaking TUIC: the client's streams and connections are all that
// the tests look at.
func sinkServer(t *testing.T) string {
	t.Helper()
	certPEM, keyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	require.NoError(t, err)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}, &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 30 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				for {
					stream, err := conn.AcceptUniStream(context.Background())
					if err != nil {
						return
					}
					go func() { _, _ = io.Copy(io.Discard, stream) }()
				}
			}()
			go func() {
				for {
					stream, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func() { _, _ = io.Copy(io.Discard, stream) }()
				}
			}()
		}
	}()
	return listener.Addr().String()
}

// testClient returns a client whose every dial makes a new connection to a
// sinkServer, and the connections it made.
func testClient(t *testing.T) (*clientImpl, *[]*quic.Conn) {
	t.Helper()
	addr := sinkServer(t)
	conns := new([]*quic.Conn)
	client := &clientImpl{
		ClientOption: &ClientOption{MaxOpenStreams: 100},
		dialFn: func(ctx context.Context) (*quic.Conn, error) {
			conn, err := quic.DialAddr(ctx, addr, &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h3"},
			}, &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 30 * time.Second})
			if err == nil {
				*conns = append(*conns, conn)
				t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
			}
			return conn, err
		},
	}
	return client, conns
}

func isClosed(conn *quic.Conn) bool {
	select {
	case <-conn.Context().Done():
		return true
	default:
		return false
	}
}

// The open stream count covers the streams of a connection that was
// replaced, and a closed client closes its current connection once the last
// stream drains, even when that stream outlived an older connection.
func TestClientOpenStreamsAcrossReconnect(t *testing.T) {
	client, conns := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	metadata := &C.Metadata{Host: "example.com", DstPort: 443}

	old, err := client.DialContext(ctx, metadata)
	require.NoError(t, err)
	client.forceClose(nil, types.ClientClosed) // the connection fails: the next dial reconnects
	current, err := client.DialContext(ctx, metadata)
	require.NoError(t, err)
	require.Len(t, *conns, 2)
	require.EqualValues(t, 2, client.OpenStreams(), "the stream on the replaced connection still counts")

	client.Close()
	require.False(t, isClosed((*conns)[1]), "closed with a stream open")
	_ = current.Close()
	time.Sleep(100 * time.Millisecond)
	_ = old.Close() // drains last
	require.Eventually(t, func() bool { return client.OpenStreams() == 0 }, 2*C.DefaultTCPTimeout, 50*time.Millisecond)
	require.Eventually(t, func() bool { return isClosed((*conns)[1]) }, 5*time.Second, 50*time.Millisecond,
		"the current connection is open after the last stream drained")
}
