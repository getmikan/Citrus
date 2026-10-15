package trojan

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/trojan"
)

const testMuxStreams = 3

func TestMain(m *testing.M) {
	// set before any listener goroutine reads it
	maxMuxStreams = testMuxStreams
	os.Exit(m.Run())
}

// smux protocol version 1, as the server speaks it (smux.DefaultConfig)
const (
	smuxVersion = 1
	smuxSYN     = 0
	smuxFIN     = 1
	smuxPSH     = 2
)

// muxConn is the client side of a Trojan mux session, speaking raw smux
// frames. The smux client cannot be used to see a refused stream: its
// OpenStream sends the SYN before it registers the stream, and its receive
// loop drops a FIN for a stream it does not know, so when the server closes
// the stream at once the client may never get EOF on it.
type muxConn struct {
	t    *testing.T
	conn net.Conn
}

type muxFrame struct {
	cmd  byte
	sid  uint32
	data []byte
}

func openMux(t *testing.T, client net.Conn) *muxConn {
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
	return &muxConn{t: t, conn: client}
}

func (m *muxConn) write(cmd byte, sid uint32, payload []byte) {
	m.t.Helper()
	frame := make([]byte, 8, 8+len(payload))
	frame[0] = smuxVersion
	frame[1] = cmd
	binary.LittleEndian.PutUint16(frame[2:], uint16(len(payload)))
	binary.LittleEndian.PutUint32(frame[4:], sid)
	if _, err := m.conn.Write(append(frame, payload...)); err != nil {
		m.t.Fatal(err)
	}
}

// read returns the next frame from the server; within only bounds the wait
// for it.
func (m *muxConn) read(within time.Duration) muxFrame {
	m.t.Helper()
	_ = m.conn.SetReadDeadline(time.Now().Add(within))
	var hdr [8]byte
	if _, err := io.ReadFull(m.conn, hdr[:]); err != nil {
		m.t.Fatalf("no mux frame from the server: %v", err)
	}
	if hdr[0] != smuxVersion {
		m.t.Fatalf("mux frame of version %d", hdr[0])
	}
	f := muxFrame{
		cmd:  hdr[1],
		sid:  binary.LittleEndian.Uint32(hdr[4:]),
		data: make([]byte, binary.LittleEndian.Uint16(hdr[2:])),
	}
	if _, err := io.ReadFull(m.conn, f.data); err != nil {
		m.t.Fatalf("mux frame payload: %v", err)
	}
	return f
}

// reply opens stream sid with a TCP request carrying payload and returns what
// the server answers on it: the echo, or nil when it closes the stream first.
// Frames of other streams (such as the FIN of a finished one) are skipped.
func (m *muxConn) reply(sid uint32, payload string) []byte {
	m.t.Helper()
	m.write(smuxSYN, sid, nil)
	m.write(smuxPSH, sid, append(muxRequest(), payload...))
	var got []byte
	for len(got) < len(payload) {
		f := m.read(5 * time.Second)
		if f.sid != sid {
			continue
		}
		switch f.cmd {
		case smuxFIN:
			return nil
		case smuxPSH:
			got = append(got, f.data...)
		}
	}
	return got
}

// muxRequest is the header of a TCP request inside a mux stream.
func muxRequest() []byte {
	return append([]byte{trojan.CommandTCP}, socks5.ParseAddr("1.2.3.4:80")...)
}

// One client used to get a goroutine for every mux stream it opened, with no
// limit; beyond maxMuxStreams a stream is now closed at once and the session
// keeps working.
func TestTrojanMuxStreamCap(t *testing.T) {
	client := serveTrojanOnce(t, 0)
	m := openMux(t, client)

	// client stream IDs are odd; the held streams send no header, so each
	// holds a server goroutine (for the 15s handshake timeout)
	sid := uint32(1)
	held := make([]uint32, 0, testMuxStreams)
	for i := 0; i < testMuxStreams; i++ {
		sid += 2
		held = append(held, sid)
		m.write(smuxSYN, sid, nil)
	}
	sid += 2
	over := sid
	m.write(smuxSYN, over, nil)

	// the server accepts streams in order and counts each before it accepts
	// the next, so the one over the cap is refused, and as the held streams
	// are silent its FIN is the first frame of the session
	if f := m.read(5 * time.Second); f.cmd != smuxFIN || f.sid != over {
		t.Fatalf("expected the FIN of stream %d, got cmd %d on stream %d", over, f.cmd, f.sid)
	}

	// the held streams still work
	m.write(smuxPSH, held[0], append(muxRequest(), "hello"...))
	var got []byte
	for len(got) < 5 {
		f := m.read(5 * time.Second)
		if f.sid != held[0] || f.cmd != smuxPSH {
			t.Fatalf("stream within the cap: cmd %d on stream %d, after %q", f.cmd, f.sid, got)
		}
		got = append(got, f.data...)
	}
	if string(got) != "hello" {
		t.Fatalf("stream within the cap: %q", got)
	}

	// and the slot freed by that finished stream is usable again. The client
	// cannot see the moment the server releases it (just after the stream's
	// FIN), so a stream opened before then is refused and the next one tried;
	// every attempt gets a definite answer.
	deadline := time.Now().Add(5 * time.Second)
	for {
		sid += 2
		resp := m.reply(sid, "again")
		if resp != nil {
			if string(resp) != "again" {
				t.Fatalf("unexpected response %q", resp)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("freed slot was not reused")
		}
	}
}

// A mux stream that never sends its request header is closed at the
// handshake deadline.
func TestTrojanMuxStreamHandshakeTimeout(t *testing.T) {
	shortHandshakeTimeout(t, 200*time.Millisecond)
	client := serveTrojanOnce(t, 0)
	m := openMux(t, client)
	m.write(smuxSYN, 3, nil)
	if f := m.read(5 * time.Second); f.cmd != smuxFIN || f.sid != 3 {
		t.Fatalf("expected the FIN of stream 3, got cmd %d on stream %d", f.cmd, f.sid)
	}
}
