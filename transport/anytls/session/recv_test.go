package session

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/transport/anytls/util"

	N "github.com/metacubex/sing/common/network"
)

// rawServer runs a server session on one end of a pipe and returns the other
// end, with the settings already sent, and the streams the server opens.
func rawServer(t *testing.T) (net.Conn, *Session, <-chan *Stream) {
	t.Helper()
	pad := newTestPadding()
	clientConn, serverConn := net.Pipe()
	streams := make(chan *Stream, 16)
	server := NewServerSession(serverConn, func(stream *Stream) { streams <- stream }, pad)
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.Run()
		server.Close()
	}()
	// the server's own frames (SYNACKs, FINs) are not looked at
	go func() { _, _ = io.Copy(io.Discard, clientConn) }()
	t.Cleanup(func() {
		_ = clientConn.Close()
		<-done
	})
	settings := util.StringMap{"v": "2", "client": "test", "padding-md5": pad.Load().Md5}
	mustWrite(t, clientConn, rawFrame(cmdSettings, 0, settings.ToBytes()))
	return clientConn, server, streams
}

func mustWrite(t *testing.T, w io.Writer, b []byte) {
	t.Helper()
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
}

func nextStream(t *testing.T, streams <-chan *Stream) *Stream {
	t.Helper()
	select {
	case s := <-streams:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("no stream")
		return nil
	}
}

// writeAsync writes b in the background: net.Pipe blocks a write until the
// session reads it, which a full session does not.
func writeAsync(w io.Writer, b []byte) <-chan error {
	ch := make(chan error, 1)
	go func() {
		_, err := w.Write(b)
		ch <- err
	}()
	return ch
}

// lowerRecvBudget sets recvBudget for a test. Called before rawServer, its
// cleanup runs after the session's (cleanups run last first), once the
// session's goroutines are gone.
func lowerRecvBudget(t *testing.T, budget int64) {
	old := recvBudget
	recvBudget = budget
	t.Cleanup(func() { recvBudget = old })
}

// Frames that arrive before the peer's FIN are still read after it; the
// reads end with the stream's close error once they are.
func TestStreamReadsDataBeforeFIN(t *testing.T) {
	conn, _, streams := rawServer(t)
	mustWrite(t, conn, rawFrame(cmdSYN, 1, nil))
	stream := nextStream(t, streams)
	mustWrite(t, conn, rawFrame(cmdPSH, 1, []byte("hello ")))
	mustWrite(t, conn, rawFrame(cmdPSH, 1, []byte("world")))
	mustWrite(t, conn, rawFrame(cmdFIN, 1, nil))
	// the FIN has been handled once a frame after it is read
	mustWrite(t, conn, rawFrame(cmdHeartResponse, 0, nil))

	got, err := io.ReadAll(stream)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read ended with %v, want net.ErrClosed", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("read %q", got)
	}
}

// recvLoop stops reading the connection while the session holds more than
// recvBudget for its readers, and goes on once a reader takes the data.
func TestSessionRecvBudget(t *testing.T) {
	lowerRecvBudget(t, 1000)

	conn, server, streams := rawServer(t)
	mustWrite(t, conn, rawFrame(cmdSYN, 1, nil))
	mustWrite(t, conn, rawFrame(cmdSYN, 3, nil))
	slow := nextStream(t, streams)
	other := nextStream(t, streams)
	if slow.id != 1 {
		slow, other = other, slow
	}

	big := bytes.Repeat([]byte("x"), 1500)
	mustWrite(t, conn, rawFrame(cmdPSH, 1, big)) // over the budget: recvLoop waits
	blocked := writeAsync(conn, rawFrame(cmdPSH, 3, []byte("next")))
	select {
	case err := <-blocked:
		t.Fatalf("session read a frame over its budget (%v)", err)
	case <-time.After(100 * time.Millisecond):
	}
	if q := server.recvQueued.Load(); q != int64(len(big)) {
		t.Fatalf("queued %d, want %d", q, len(big))
	}

	got := make([]byte, len(big))
	if _, err := io.ReadFull(slow, got); err != nil {
		t.Fatal(err)
	}
	if err := <-blocked; err != nil {
		t.Fatal(err)
	}
	next := make([]byte, 4)
	if _, err := io.ReadFull(other, next); err != nil || string(next) != "next" {
		t.Fatalf("read %q, %v", next, err)
	}
	if q := server.recvQueued.Load(); q != 0 {
		t.Fatalf("queued %d after the reads", q)
	}
}

// A stream closed locally drops what it has not read, and gives the budget
// back so that the session goes on.
func TestStreamCloseReleasesQueue(t *testing.T) {
	lowerRecvBudget(t, 1000)

	conn, server, streams := rawServer(t)
	mustWrite(t, conn, rawFrame(cmdSYN, 1, nil))
	stream := nextStream(t, streams)
	mustWrite(t, conn, rawFrame(cmdPSH, 1, bytes.Repeat([]byte("x"), 1500)))
	blocked := writeAsync(conn, rawFrame(cmdPSH, 1, []byte("dropped")))
	time.Sleep(50 * time.Millisecond)

	stream.Close()
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session still waits after the stream closed")
	}
	mustWrite(t, conn, rawFrame(cmdHeartResponse, 0, nil))
	if q := server.recvQueued.Load(); q != 0 {
		t.Fatalf("queued %d after the close", q)
	}
	if _, err := stream.Read(make([]byte, 8)); err == nil {
		t.Fatal("read on a closed stream succeeded")
	}
}

// The read waiter hands over the frames themselves, in order; the batch
// variant takes every queued frame at once.
func TestStreamReadWaiter(t *testing.T) {
	conn, _, streams := rawServer(t)
	mustWrite(t, conn, rawFrame(cmdSYN, 1, nil))
	stream := nextStream(t, streams)

	var rw N.ReadWaiter = stream
	if rw.InitializeReadWaiter(N.ReadWaitOptions{}) {
		t.Fatal("read waiter asks for a copy")
	}
	mustWrite(t, conn, rawFrame(cmdPSH, 1, []byte("one")))
	b, err := stream.WaitReadBuffer()
	if err != nil || string(b.Bytes()) != "one" {
		t.Fatalf("got %v, %v", b, err)
	}
	b.Release()

	mustWrite(t, conn, rawFrame(cmdPSH, 1, []byte("two")))
	mustWrite(t, conn, rawFrame(cmdPSH, 1, []byte("three")))
	mustWrite(t, conn, rawFrame(cmdHeartResponse, 0, nil))
	batch, err := stream.WaitReadBuffers()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, b := range batch {
		got = append(got, string(b.Bytes()))
	}
	buf.ReleaseMulti(batch)
	if len(got) != 2 || got[0] != "two" || got[1] != "three" {
		t.Fatalf("batch %q", got)
	}

	// a destination with headroom gets it
	stream.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 16, RearHeadroom: 8})
	mustWrite(t, conn, rawFrame(cmdPSH, 1, []byte("four")))
	b, err = stream.WaitReadBuffer()
	if err != nil || string(b.Bytes()) != "four" || b.Start() < 16 || b.FreeLen() < 8 {
		t.Fatalf("got %v, %v", b, err)
	}
	b.Release()
}

func TestStreamReadDeadline(t *testing.T) {
	conn, _, streams := rawServer(t)
	mustWrite(t, conn, rawFrame(cmdSYN, 1, nil))
	stream := nextStream(t, streams)

	stream.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := stream.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read ended with %v", err)
	}
	stream.SetReadDeadline(time.Time{})
	mustWrite(t, conn, rawFrame(cmdPSH, 1, []byte("late")))
	got := make([]byte, 4)
	if _, err := io.ReadFull(stream, got); err != nil || string(got) != "late" {
		t.Fatalf("read %q, %v", got, err)
	}
}
