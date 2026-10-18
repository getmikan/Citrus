package session

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/metacubex/mihomo/common/buf"
)

// readFrames reads n frames off the wire of a server session.
func readFrames(t *testing.T, r io.Reader, n int) []gotFrame {
	t.Helper()
	frames := make([]gotFrame, 0, n)
	for i := 0; i < n; i++ {
		var hdr rawHeader
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, hdr.Length())
		if _, err := io.ReadFull(r, data); err != nil {
			t.Fatal(err)
		}
		frames = append(frames, gotFrame{cmd: hdr.Cmd(), sid: hdr.StreamID(), data: string(data)})
	}
	return frames
}

// Stream.WriteBuffer builds the frame in the buffer's headroom when there is
// room, and falls back to a copy otherwise; the wire is the same either way.
func TestStreamWriteBuffer(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	server := NewServerSession(serverConn, nil, newTestPadding())
	defer server.Close()
	stream := newStream(5, server)

	payload := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB

	cases := []struct {
		name     string
		buffer   func() *buf.Buffer
		frames   int
		dataLens []int
	}{
		{"headroom", func() *buf.Buffer {
			b := buf.NewSize(stream.FrontHeadroom() + 1000)
			b.Resize(stream.FrontHeadroom(), 0)
			b.Write(payload[:1000])
			return b
		}, 1, []int{1000}},
		{"no headroom", func() *buf.Buffer {
			b := buf.NewSize(1000)
			b.Write(payload[:1000])
			return b
		}, 1, []int{1000}},
		{"over a frame", func() *buf.Buffer {
			b := buf.NewSize(stream.FrontHeadroom() + len(payload))
			b.Resize(stream.FrontHeadroom(), 0)
			b.Write(payload)
			return b
		}, 2, []int{maxFrameDataLen, len(payload) - maxFrameDataLen}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errCh := make(chan error, 1)
			go func() { errCh <- stream.WriteBuffer(c.buffer()) }()
			frames := readFrames(t, clientConn, c.frames)
			if err := <-errCh; err != nil {
				t.Fatal(err)
			}
			var got []byte
			for i, f := range frames {
				if f.cmd != cmdPSH || f.sid != 5 || len(f.data) != c.dataLens[i] {
					t.Fatalf("frame %d: cmd %d sid %d len %d", i, f.cmd, f.sid, len(f.data))
				}
				got = append(got, f.data...)
			}
			if !bytes.Equal(got, payload[:len(got)]) {
				t.Fatal("payload mismatch")
			}
		})
	}

	// an empty buffer writes nothing
	if err := stream.WriteBuffer(buf.NewSize(16)); err != nil {
		t.Fatal(err)
	}
	// a closed stream refuses the buffer
	stream.closeLocally()
	if err := stream.WriteBuffer(buf.As([]byte("x"))); err == nil {
		t.Fatal("write on a closed stream succeeded")
	}
}
