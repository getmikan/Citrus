package multiplex

import (
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

type rawFrame struct {
	typ     byte
	id      uint32
	payload []byte
}

func setStreamLimit(t *testing.T, limit int) {
	t.Helper()
	old := maxStreamsPerSession
	maxStreamsPerSession = limit
	t.Cleanup(func() { maxStreamsPerSession = old })
}

// rawPeer drives a server session with hand-written frames and collects what
// the server sends back.
func rawPeer(t *testing.T) (*Session, net.Conn, <-chan rawFrame) {
	t.Helper()
	peerConn, serverConn := net.Pipe()
	server, err := NewServerSession(serverConn)
	if err != nil {
		t.Fatalf("new server session: %v", err)
	}
	frames := make(chan rawFrame, 1024)
	go func() {
		defer close(frames)
		var header [headerSize]byte
		for {
			if _, err := io.ReadFull(peerConn, header[:]); err != nil {
				return
			}
			f := rawFrame{typ: header[0], id: binary.BigEndian.Uint32(header[1:5])}
			if n := binary.BigEndian.Uint32(header[5:9]); n > 0 {
				f.payload = make([]byte, n)
				if _, err := io.ReadFull(peerConn, f.payload); err != nil {
					return
				}
			}
			frames <- f
		}
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = peerConn.Close()
	})
	return server, peerConn, frames
}

func writeRawFrame(t *testing.T, conn net.Conn, typ byte, id uint32, payload []byte) {
	t.Helper()
	var header [headerSize]byte
	header[0] = typ
	binary.BigEndian.PutUint32(header[1:5], id)
	binary.BigEndian.PutUint32(header[5:9], uint32(len(payload)))
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(append(header[:], payload...)); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

func waitReset(t *testing.T, frames <-chan rawFrame, id uint32) string {
	t.Helper()
	timeout := time.After(2 * time.Second)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatalf("session closed before RESET for stream %d", id)
			}
			if f.typ == frameReset && f.id == id {
				return string(f.payload)
			}
		case <-timeout:
			t.Fatalf("no RESET for stream %d", id)
		}
	}
}

func TestServerSessionRefusesOpenBeyondStreamLimit(t *testing.T) {
	setStreamLimit(t, 4)
	server, peer, frames := rawPeer(t)

	for id := uint32(1); id <= 4; id++ {
		writeRawFrame(t, peer, frameOpen, id, nil)
	}
	writeRawFrame(t, peer, frameOpen, 5, nil)
	if msg := waitReset(t, frames, 5); msg != "too many streams" {
		t.Fatalf("RESET reason = %q", msg)
	}

	// closing an accepted stream frees its slot
	conn, _, err := server.AcceptStream()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	_ = conn.Close()
	writeRawFrame(t, peer, frameOpen, 6, nil)
	writeRawFrame(t, peer, frameOpen, 7, nil)
	if msg := waitReset(t, frames, 7); msg != "too many streams" {
		t.Fatalf("RESET reason = %q", msg)
	}
	for i := 0; i < 4; i++ {
		conn, _, err := server.AcceptStream()
		if err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
		if id := conn.(*stream).id; id == 5 || id == 7 {
			t.Fatalf("refused stream %d was accepted", id)
		}
	}
}

// Streams that are never accepted must not each pin a goroutine.
func TestServerSessionOpenDoesNotSpawnGoroutines(t *testing.T) {
	setStreamLimit(t, 4096)
	_, peer, _ := rawPeer(t)

	before := runtime.NumGoroutine()
	for id := uint32(1); id <= 2000; id++ {
		writeRawFrame(t, peer, frameOpen, id, nil)
	}
	// a DATA frame after the OPENs makes sure the read loop handled them all
	writeRawFrame(t, peer, frameData, 0, nil)
	time.Sleep(50 * time.Millisecond)
	if after := runtime.NumGoroutine(); after-before > 100 {
		t.Fatalf("goroutines grew from %d to %d for unaccepted streams", before, after)
	}
}

// A client may open hundreds of streams before the server accepts any of them.
func TestServerSessionAcceptsBurstUnderLimit(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	client, err := NewClientSession(clientConn)
	if err != nil {
		t.Fatalf("new client session: %v", err)
	}
	server, err := NewServerSession(serverConn)
	if err != nil {
		t.Fatalf("new server session: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	const n = 600
	opened := make([]net.Conn, 0, n)
	for i := 0; i < n; i++ {
		c, err := client.OpenStream([]byte{byte(i)})
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		opened = append(opened, c)
	}
	for i := 0; i < n; i++ {
		c, payload, err := server.AcceptStream()
		if err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
		if len(payload) != 1 || payload[0] != byte(i) {
			t.Fatalf("accept %d: payload %v", i, payload)
		}
		_ = c.Close()
	}
	for _, c := range opened {
		_ = c.Close()
	}
}
