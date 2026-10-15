package mixed

import (
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"

	"github.com/stretchr/testify/require"
)

type nopTunnel struct{}

func (nopTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata)        { _ = conn.Close() }
func (nopTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {}
func (nopTunnel) NatTable() C.NatTable                                     { return nil }

func TestMixedSilentClientTimesOut(t *testing.T) {
	old := authStore.HandshakeTimeout
	authStore.HandshakeTimeout = 100 * time.Millisecond
	t.Cleanup(func() { authStore.HandshakeTimeout = old })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		handleConn(c, nopTunnel{}, authStore.Nil)
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer client.Close()

	// sends nothing: not even the first byte that picks the protocol
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a client that sends nothing is never dropped")
	}
}
