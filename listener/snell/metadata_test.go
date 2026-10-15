package snell

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/transport/snell"

	"github.com/stretchr/testify/require"
)

type addrConn struct{ net.Conn }

func (addrConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 40000} }
func (addrConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 8388} }

// The user an outer layer (ShadowTLS, JLS) verified reaches the metadata;
// without one there is no user.
func TestMetadataKeepsVerifiedUser(t *testing.T) {
	l := &Listener{}
	base := []inbound.Addition{inbound.WithInName("snell-in")}

	verified := append(append([]inbound.Addition(nil), base...), inbound.WithInUser("alice"))
	m := l.metadata(C.TCP, "1.2.3.4", 443, addrConn{}, verified...)
	require.Equal(t, "alice", m.InUser)
	require.Equal(t, "snell-in", m.InName)

	m = l.metadata(C.UDP, "1.2.3.4", 53, addrConn{}, verified...)
	require.Equal(t, "alice", m.InUser)

	m = l.metadata(C.TCP, "1.2.3.4", 443, addrConn{}, base...)
	require.Empty(t, m.InUser)
}

// metadataTunnel records the metadata of the first TCP request.
type metadataTunnel struct {
	got chan *C.Metadata
}

func (tt metadataTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	conn.Close()
	tt.got <- metadata
}

func (tt metadataTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {}

func (tt metadataTunnel) NatTable() C.NatTable { return nil }

// A client that knows the PSK cannot name a user with the Snell client ID:
// the ID is consumed and the request still parses, but IN-USER stays empty.
func TestSnellClientIDDoesNotNameUser(t *testing.T) {
	for _, id := range []string{"", "alice", string(make([]byte, 255))} {
		tt := metadataTunnel{got: make(chan *C.Metadata, 1)}
		l := &Listener{config: LC.SnellServer{Psk: testPSK, Version: snell.Version4}}
		server, client := net.Pipe()
		go l.HandleConn(server, tt)

		stream := snell.StreamConn(client, []byte(testPSK), snell.Version4)
		header := []byte{snell.Version, snell.CommandConnect, byte(len(id))}
		header = append(header, id...)
		host := "example.com"
		header = append(header, byte(len(host)))
		header = append(header, host...)
		header = append(header, 0x01, 0xbb)
		go func() {
			_, _ = stream.Write(header)
			_, _ = io.Copy(io.Discard, stream)
		}()

		select {
		case m := <-tt.got:
			require.Empty(t, m.InUser, "client ID %q", id)
			require.Equal(t, "example.com", m.Host)
			require.EqualValues(t, 443, m.DstPort)
		case <-time.After(5 * time.Second):
			t.Fatalf("no request for client ID %q", id)
		}
		_ = client.Close()
	}
}
