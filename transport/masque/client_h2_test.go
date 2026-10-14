package masque

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/metacubex/quic-go/quicvarint"
)

func capsule(typ, length uint64, payload []byte) []byte {
	b := quicvarint.Append(nil, typ)
	b = quicvarint.Append(b, length)
	return append(b, payload...)
}

func streamOf(data []byte) *h2DatagramStream {
	return &h2DatagramStream{responseBody: io.NopCloser(bytes.NewReader(data))}
}

// A capsule length is declared by the peer; a huge one must be refused before
// anything is allocated for it (it used to go straight to make).
func TestReceiveDatagramRejectsOversizedCapsule(t *testing.T) {
	for _, tc := range []struct {
		name   string
		typ    uint64
		length uint64
	}{
		{"datagram max varint", h2DatagramCapsuleType, quicvarint.Max},
		{"datagram above IP max", h2DatagramCapsuleType, maxH2DatagramCapsuleLen + 1},
		{"other max varint", 0x1ACE, quicvarint.Max},
		{"other above cap", 0x1ACE, maxH2OtherCapsuleLen + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := streamOf(capsule(tc.typ, tc.length, make([]byte, 64)))
			if _, err := s.ReceiveDatagram(context.Background()); err == nil {
				t.Fatal("oversized capsule accepted")
			}
		})
	}
}

func TestReceiveDatagramSkipsOtherCapsules(t *testing.T) {
	packet := make([]byte, maxH2DatagramCapsuleLen)
	packet[0] = 0x45
	var data []byte
	data = append(data, capsule(0x1ACE, 3, []byte{1, 2, 3})...)
	data = append(data, capsule(h2DatagramCapsuleType, uint64(len(packet)), packet)...)
	got, err := streamOf(data).ReceiveDatagram(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, packet) {
		t.Fatalf("got %d bytes, want the %d-byte packet", len(got), len(packet))
	}
}
