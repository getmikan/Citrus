package sniffer

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
)

func TestBitTorrentDefaultPortsSkipServerFirst(t *testing.T) {
	bt, err := NewBitTorrentSniffer(SnifferConfig{})
	assert.NoError(t, err)

	for _, port := range bitTorrentServerFirstPorts {
		assert.False(t, bt.SupportPort(port), "port %d", port)
	}
	for _, port := range []uint16{1, 20, 24, 80, 443, 6881, 6889, 51413, 65535} {
		assert.True(t, bt.SupportPort(port), "port %d", port)
	}

	// an explicit port list is taken as is
	bt, err = NewBitTorrentSniffer(SnifferConfig{Ports: utils.IntRanges[uint16]{utils.NewRange[uint16](22, 22)}})
	assert.NoError(t, err)
	assert.True(t, bt.SupportPort(22))
	assert.False(t, bt.SupportPort(6881))
}

// A client of a server-first protocol sends nothing until the server greets
// it. Protocol sniffing has to give up on it quickly instead of holding the
// connection for the full domain sniffing window, and leave it intact.
func TestProtocolSniffDoesNotStallServerFirst(t *testing.T) {
	sd := newBitTorrentDispatcher(t)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("198.51.100.7"), DstPort: 2222}
	conn := N.NewBufferedConn(server)

	start := time.Now()
	assert.False(t, sd.TCPSniff(conn, metadata))
	elapsed := time.Since(start)
	assert.Empty(t, metadata.SniffProtocol)
	assert.GreaterOrEqual(t, elapsed, protocolSniffTimeout)
	assert.Less(t, elapsed, protocolSniffTimeout+400*time.Millisecond)

	// the connection still works once the client starts talking
	go func() {
		_, _ = client.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
	}()
	buf := make([]byte, 21)
	_, err := io.ReadFull(conn, buf)
	assert.NoError(t, err)
	assert.Equal(t, "SSH-2.0-OpenSSH_9.6\r\n", string(buf))
}

// a handshake split across segments is still recognised
func TestProtocolSniffSplitHandshake(t *testing.T) {
	sd := newBitTorrentDispatcher(t)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = client.Write(gatingHandshake[:5])
		time.Sleep(protocolSniffTimeout / 3)
		_, _ = client.Write(gatingHandshake[5:])
	}()

	metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("198.51.100.7"), DstPort: 6881}
	assert.False(t, sd.TCPSniff(N.NewBufferedConn(server), metadata))
	assert.Equal(t, C.ProtocolBitTorrent, metadata.SniffProtocol)
}
