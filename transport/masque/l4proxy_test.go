package masque

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

// Failed CONNECTs give their streams back: with a peer that allows a few
// streams at once and keeps a rejected one until the client ends it, many
// more CONNECTs than that are each answered, none waits for a stream that
// a failed one still holds.
func TestL4ClientFailedConnectReleasesStream(t *testing.T) {
	const maxStreams = 4
	certPEM, keyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	require.NoError(t, err)
	listener, err := quic.ListenAddrEarly("127.0.0.1:0", http3.ConfigureTLSConfig(&tls.Config{
		Certificates: []tls.Certificate{cert},
	}), &quic.Config{MaxIncomingStreams: maxStreams, MaxIdleTimeout: 30 * time.Second})
	require.NoError(t, err)
	server := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// answer, and read the tunnel to its end, as a proxy that relays
		// it does: the stream stays open until the client ends or resets it
		w.WriteHeader(http.StatusForbidden)
		w.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, r.Body)
	})}
	go func() { _ = server.ServeListener(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = listener.Close() })

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := NewL4Client(runCtx, func(ctx context.Context) (net.PacketConn, *quic.Conn, error) {
		conn, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		}, &quic.Config{MaxIdleTimeout: 30 * time.Second})
		return nil, conn, err
	})
	defer client.Close()

	for i := 0; i < 4*maxStreams; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := client.DialContext(ctx, "tcp", "example.com:443")
		cancel()
		require.ErrorContains(t, err, "status 403", "CONNECT %d", i)
	}
}
