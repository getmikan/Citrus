package shadowquic

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"

	"github.com/metacubex/jls-quic-go"
	"github.com/metacubex/jls-tls"
	"github.com/stretchr/testify/require"
)

// stalledPeerAssociation returns a udp-over-stream association on a QUIC
// connection (with datagrams, which connState needs) to a peer that accepts
// no streams and reads nothing: the
// peer's serverConf decides where the association's writes stall.
func stalledPeerAssociation(t *testing.T, serverConf *quic.Config) *association {
	t.Helper()
	certPEM, keyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	require.NoError(t, err)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"test"},
	}, serverConf)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan *quic.Conn, 1)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err == nil {
			accepted <- conn
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"test"},
	}, &quic.Config{MaxIdleTimeout: 30 * time.Second, EnableDatagrams: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	select {
	case peer := <-accepted:
		t.Cleanup(func() { _ = peer.CloseWithError(0, "") })
	case <-ctx.Done():
		t.Fatal("no connection accepted")
	}

	control, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	a := newAssociation(newConnState(conn), control, udpModeStream)
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// writeUntilBlocked writes packets until a write does not return within a
// moment, and returns the result of that write once it does.
func writeUntilBlocked(t *testing.T, a *association) <-chan error {
	t.Helper()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
	payload := make([]byte, 1200)
	for i := 0; i < 1000; i++ {
		result := make(chan error, 1)
		go func() {
			_, err := a.WriteTo(payload, addr)
			result <- err
		}()
		select {
		case err := <-result:
			require.NoError(t, err)
		case <-time.After(200 * time.Millisecond):
			return result
		}
	}
	t.Fatal("the writes never stalled")
	return nil
}

func requireReturns(t *testing.T, ch <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("%s still blocked", what)
		return nil
	}
}

func closeAsync(a *association) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- a.Close() }()
	return ch
}

// The peer grants no stream: opening the packet stream waits for credit,
// and Close ends the wait instead of waiting for it.
func TestAssociationCloseDuringStreamOpen(t *testing.T) {
	a := stalledPeerAssociation(t, &quic.Config{MaxIncomingUniStreams: -1, MaxIdleTimeout: 30 * time.Second, EnableDatagrams: true})
	blocked := writeUntilBlocked(t, a)
	closed := closeAsync(a)
	err := requireReturns(t, blocked, "WriteTo")
	require.ErrorIs(t, err, net.ErrClosed)
	requireReturns(t, closed, "Close")
}

// The same wait ends at the write deadline.
func TestAssociationWriteDeadlineDuringStreamOpen(t *testing.T) {
	a := stalledPeerAssociation(t, &quic.Config{MaxIncomingUniStreams: -1, MaxIdleTimeout: 30 * time.Second, EnableDatagrams: true})
	require.NoError(t, a.SetWriteDeadline(time.Now().Add(300*time.Millisecond)))
	_, err := a.WriteTo(make([]byte, 100), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
}

// The peer reads nothing from the packet stream: a write waits for flow
// control credit, and Close ends it instead of waiting for it.
func TestAssociationCloseDuringStreamWrite(t *testing.T) {
	a := stalledPeerAssociation(t, &quic.Config{MaxIncomingUniStreams: 16, InitialStreamReceiveWindow: 16 << 10, MaxStreamReceiveWindow: 16 << 10, MaxIdleTimeout: 30 * time.Second, EnableDatagrams: true})
	blocked := writeUntilBlocked(t, a)
	closed := closeAsync(a)
	err := requireReturns(t, blocked, "WriteTo")
	require.ErrorIs(t, err, net.ErrClosed)
	requireReturns(t, closed, "Close")
}

// The same write ends at a write deadline set while it waits, and the
// stream it left a part of a packet on is not written again.
func TestAssociationWriteDeadlineDuringStreamWrite(t *testing.T) {
	a := stalledPeerAssociation(t, &quic.Config{MaxIncomingUniStreams: 16, InitialStreamReceiveWindow: 16 << 10, MaxStreamReceiveWindow: 16 << 10, MaxIdleTimeout: 30 * time.Second, EnableDatagrams: true})
	blocked := writeUntilBlocked(t, a)
	require.NoError(t, a.SetWriteDeadline(time.Now()))
	err := requireReturns(t, blocked, "WriteTo")
	require.True(t, errors.Is(err, os.ErrDeadlineExceeded), "write ended with %v", err)
	a.mu.Lock()
	streams := len(a.uniStreams)
	a.mu.Unlock()
	require.Zero(t, streams)
}
