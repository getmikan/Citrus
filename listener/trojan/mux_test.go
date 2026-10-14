package trojan

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/trojan"

	"github.com/metacubex/smux"
)

const testMuxStreams = 3

func TestMain(m *testing.M) {
	// set before any listener goroutine reads it
	maxMuxStreams = testMuxStreams
	os.Exit(m.Run())
}

func openMux(t *testing.T, client net.Conn) *smux.Session {
	t.Helper()
	var b bytes.Buffer
	key := trojan.Key(testPassword)
	b.Write(key[:])
	b.WriteString("\r\n")
	b.WriteByte(trojan.CommandMux)
	b.Write(socks5.ParseAddr("1.2.3.4:80"))
	b.WriteString("\r\n")
	if _, err := client.Write(b.Bytes()); err != nil {
		t.Fatal(err)
	}
	cfg := smux.DefaultConfig()
	cfg.KeepAliveDisabled = true
	sess, err := smux.Client(client, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

// muxRequest is the header of a TCP request inside a mux stream.
func muxRequest() []byte {
	return append([]byte{trojan.CommandTCP}, socks5.ParseAddr("1.2.3.4:80")...)
}

func expectStreamClosed(t *testing.T, s *smux.Stream, within time.Duration) {
	t.Helper()
	_ = s.SetReadDeadline(time.Now().Add(within))
	_, err := s.Read(make([]byte, 1))
	var ne net.Error
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("stream %d still open after %v", s.ID(), within)
	}
	if err == nil {
		t.Fatalf("stream %d got data", s.ID())
	}
}

// One client used to get a goroutine for every mux stream it opened, with no
// limit; beyond maxMuxStreams a stream is now closed at once and the session
// keeps working.
func TestTrojanMuxStreamCap(t *testing.T) {
	client := serveTrojanOnce(t, 0)
	sess := openMux(t, client)

	held := make([]*smux.Stream, 0, testMuxStreams)
	for i := 0; i < testMuxStreams; i++ {
		s, err := sess.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, s) // no header: each holds a server goroutine
	}
	over, err := sess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	expectStreamClosed(t, over, 3*time.Second)

	// the held streams still work
	s := held[0]
	if _, err := s.Write(append(muxRequest(), "hello"...)); err != nil {
		t.Fatal(err)
	}
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 5)
	if _, err := io.ReadFull(s, resp); err != nil || string(resp) != "hello" {
		t.Fatalf("stream within the cap: %q, %v", resp, err)
	}
	_ = s.Close()

	// and a slot freed by a finished stream is usable again
	var again *smux.Stream
	deadline := time.Now().Add(5 * time.Second)
	for {
		again, err = sess.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = again.Write(append(muxRequest(), "again"...)); err != nil {
			t.Fatal(err)
		}
		_ = again.SetReadDeadline(time.Now().Add(time.Second))
		if _, err = io.ReadFull(again, resp); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("freed slot was not reused: %v", err)
		}
	}
	if string(resp) != "again" {
		t.Fatalf("unexpected response %q", resp)
	}
}

// A mux stream that never sends its request header is closed at the
// handshake deadline.
func TestTrojanMuxStreamHandshakeTimeout(t *testing.T) {
	shortHandshakeTimeout(t, 200*time.Millisecond)
	client := serveTrojanOnce(t, 0)
	sess := openMux(t, client)
	s, err := sess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	expectStreamClosed(t, s, 5*time.Second)
}
