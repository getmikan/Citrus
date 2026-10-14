package session

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/util"
)

func rawFrame(cmd byte, sid uint32, data []byte) []byte {
	b := make([]byte, headerOverHeadSize+len(data))
	b[0] = cmd
	binary.BigEndian.PutUint32(b[1:5], sid)
	binary.BigEndian.PutUint16(b[5:7], uint16(len(data)))
	copy(b[7:], data)
	return b
}

type gotFrame struct {
	cmd  byte
	sid  uint32
	data string
}

// A client that opens streams and never sends their destination used to get
// a stream and a blocked goroutine for every SYN. Beyond MaxServerStreams a
// SYN is now refused (SYNACK with an error, then FIN) and nothing is
// allocated for it.
func TestServerSessionCapsStreams(t *testing.T) {
	const limit, extra = 4, 6
	old := MaxServerStreams
	MaxServerStreams = limit

	pad := newTestPadding()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	var accepted atomic.Int32
	release := make(chan struct{})
	var handlers sync.WaitGroup
	var serverDone sync.WaitGroup
	serverDone.Add(1)
	go func() {
		defer serverDone.Done()
		server := NewServerSession(serverConn, func(stream *Stream) {
			handlers.Add(1)
			defer handlers.Done()
			accepted.Add(1)
			<-release // a handler stuck waiting for the destination
			stream.Close()
		}, pad)
		server.Run()
		server.Close()
	}()
	defer func() {
		close(release)
		_ = clientConn.Close()
		serverDone.Wait()
		handlers.Wait()
		MaxServerStreams = old
	}()

	frames := make(chan gotFrame, 64)
	go func() {
		var hdr rawHeader
		for {
			if _, err := io.ReadFull(clientConn, hdr[:]); err != nil {
				close(frames)
				return
			}
			data := make([]byte, hdr.Length())
			if _, err := io.ReadFull(clientConn, data); err != nil {
				close(frames)
				return
			}
			frames <- gotFrame{hdr.Cmd(), hdr.StreamID(), string(data)}
		}
	}()

	settings := util.StringMap{"v": "2", "client": "test", "padding-md5": pad.Load().Md5}
	if _, err := clientConn.Write(rawFrame(cmdSettings, 0, settings.ToBytes())); err != nil {
		t.Fatal(err)
	}
	for sid := uint32(1); sid <= limit+extra; sid++ {
		if _, err := clientConn.Write(rawFrame(cmdSYN, sid, nil)); err != nil {
			t.Fatal(err)
		}
	}

	refused := map[uint32]bool{}
	timeout := time.After(5 * time.Second)
	for len(refused) < extra {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatal("session closed")
			}
			switch f.cmd {
			case cmdSYNACK:
				if f.sid <= limit || f.data == "" {
					t.Fatalf("unexpected SYNACK for stream %d: %q", f.sid, f.data)
				}
			case cmdFIN:
				if f.sid <= limit {
					t.Fatalf("stream %d within the limit was closed", f.sid)
				}
				refused[f.sid] = true
			}
		case <-timeout:
			t.Fatalf("%d of %d streams over the limit were refused", len(refused), extra)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for accepted.Load() < limit && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepted.Load(); n != limit {
		t.Fatalf("%d streams handed to the handler, want %d", n, limit)
	}
}
