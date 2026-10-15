package trusttunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"net/netip"
	"strings"
	"testing"

	"github.com/metacubex/sing/common/buf"
)

// clientUDPFrame builds a frame as a client sends it: length, source,
// destination, app name length and payload; length is written as given.
func clientUDPFrame(length uint32, payload []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, length)
	b.Write(make([]byte, 16+2)) // source
	dst := buildPaddingIP(netip.MustParseAddr("192.0.2.1"))
	b.Write(dst[:])
	_ = binary.Write(&b, binary.BigEndian, uint16(53))
	b.WriteByte(0) // app name length
	b.Write(payload)
	return b.Bytes()
}

// serverUDPFrame builds a frame as a server sends it.
func serverUDPFrame(length uint32, payload []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, length)
	src := buildPaddingIP(netip.MustParseAddr("192.0.2.1"))
	b.Write(src[:])
	_ = binary.Write(&b, binary.BigEndian, uint16(53))
	b.Write(make([]byte, 16+2)) // local address
	b.Write(payload)
	return b.Bytes()
}

func readFromClient(data []byte, buffer *buf.Buffer) error {
	c := &serverPacketConn{}
	c.body = io.NopCloser(bytes.NewReader(data))
	_, err := c.readPacketFromClient(buffer)
	return err
}

func readFromServer(data []byte, buffer *buf.Buffer) error {
	c := &clientPacketConn{}
	c.body = io.NopCloser(bytes.NewReader(data))
	_, err := c.readPacketFromServer(buffer)
	return err
}

// The 32-bit frame length comes from the peer; a payload above the largest
// UDP datagram is refused whatever the buffer, before it is read.
func TestUDPFrameLengthBounded(t *testing.T) {
	const clientMeta, serverMeta = 16 + 2 + 16 + 2 + 1, 16 + 2 + 16 + 2
	big := make([]byte, maxUDPPayloadLen+1)
	for _, tc := range []struct {
		name string
		read func([]byte, *buf.Buffer) error
		data []byte
	}{
		{"client max uint32", readFromClient, clientUDPFrame(math.MaxUint32, nil)},
		{"client one above", readFromClient, clientUDPFrame(clientMeta+maxUDPPayloadLen+1, big)},
		{"server max uint32", readFromServer, serverUDPFrame(math.MaxUint32, nil)},
		{"server one above", readFromServer, serverUDPFrame(serverMeta+maxUDPPayloadLen+1, big)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buffer := buf.NewSize(2 * maxUDPPayloadLen)
			defer buffer.Release()
			err := tc.read(tc.data, buffer)
			if err == nil || !strings.Contains(err.Error(), "invalid udp length") {
				t.Fatalf("err = %v, want invalid udp length", err)
			}
			if buffer.Len() != 0 {
				t.Fatalf("read %d payload bytes of a rejected frame", buffer.Len())
			}
		})
	}

	largest := make([]byte, maxUDPPayloadLen)
	buffer := buf.NewSize(2 * maxUDPPayloadLen)
	defer buffer.Release()
	if err := readFromClient(clientUDPFrame(clientMeta+maxUDPPayloadLen, largest), buffer); err != nil {
		t.Fatalf("largest datagram from a client: %v", err)
	}
	buffer.Reset()
	if err := readFromServer(serverUDPFrame(serverMeta+maxUDPPayloadLen, largest), buffer); err != nil {
		t.Fatalf("largest datagram from a server: %v", err)
	}
}
