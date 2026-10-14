package gun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"runtime/debug"
	"testing"

	"github.com/metacubex/mihomo/common/httputils"
)

// frame builds one gun frame: 0x00, grpc length, 0x0A, uvarint length, payload.
func frame(grpcLen uint32, protoLen uint64, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0)
	_ = binary.Write(&b, binary.BigEndian, grpcLen)
	b.WriteByte(0x0A)
	b.Write(binary.AppendUvarint(nil, protoLen))
	b.Write(payload)
	return b.Bytes()
}

func readerConn(data []byte) *Conn {
	return &Conn{
		initFn: func(*httputils.NetAddr) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		},
		writer: io.Discard,
	}
}

// Empty frames, which a peer can send before the inner protocol has seen any
// credential, used to recurse once per frame. With a small stack limit the
// old code dies with a fatal stack overflow; the loop reads through them.
func TestReadManyEmptyFramesBoundedStack(t *testing.T) {
	const frames = 200_000
	empty := frame(2, 0, nil)
	data := bytes.Repeat(empty, frames)
	data = append(data, frame(2+5, 5, []byte("hello"))...)

	old := debug.SetMaxStack(1 << 20)
	defer debug.SetMaxStack(old)

	conn := readerConn(data)
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "hello" {
		t.Fatalf("read %q, want %q", got, "hello")
	}
}

func TestReadRejectsLengthBeyondGRPCMessage(t *testing.T) {
	for _, protoLen := range []uint64{100, 1 << 40, 1<<64 - 1} {
		conn := readerConn(frame(10, protoLen, make([]byte, 16)))
		if _, err := conn.Read(make([]byte, 16)); !errors.Is(err, ErrInvalidLength) {
			t.Fatalf("length %d: err = %v, want ErrInvalidLength", protoLen, err)
		}
	}
}

func TestReadSplitsPayloadAcrossReads(t *testing.T) {
	data := append(frame(2+6, 6, []byte("abcdef")), frame(2+2, 2, []byte("gh"))...)
	conn := readerConn(data)
	got, err := io.ReadAll(&chunkReader{conn, 4})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcdefgh" {
		t.Fatalf("read %q", got)
	}
}

type chunkReader struct {
	r io.Reader
	n int
}

func (c *chunkReader) Read(b []byte) (int, error) {
	if len(b) > c.n {
		b = b[:c.n]
	}
	return c.r.Read(b)
}
