package anytls

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbounduser"
	"github.com/metacubex/mihomo/transport/anytls/padding"
)

// serveAnyTLSOnce accepts one TCP connection and serves it with l.HandleConn.
func serveAnyTLSOnce(t *testing.T) net.Conn {
	t.Helper()
	users, _ := inbounduser.New(userKey, []C.InboundUser{{Name: "test", Secret: "password"}})
	l := &Listener{users: users}
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &l.padding)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		l.HandleConn(c, nil) // no stream is opened, so no handler is needed
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func shortHandshakeTimeout(t *testing.T, d time.Duration) {
	old := handshakeTimeout.Load()
	handshakeTimeout.Store(d)
	t.Cleanup(func() { handshakeTimeout.Store(old) })
}

func TestAnyTLSHandshakeTimeoutSilentClient(t *testing.T) {
	shortHandshakeTimeout(t, 200*time.Millisecond)
	client := serveAnyTLSOnce(t)
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := client.Read(make([]byte, 1))
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("server kept the unauthenticated conn open")
	}
	if err == nil {
		t.Fatal("server sent data to an unauthenticated client")
	}
}

func TestAnyTLSHandshakeDeadlineClearedAfterAuth(t *testing.T) {
	timeout := 200 * time.Millisecond
	shortHandshakeTimeout(t, timeout)
	client := serveAnyTLSOnce(t)
	hash := sha256.Sum256([]byte("password"))
	if _, err := client.Write(append(hash[:], 0, 0)); err != nil { // no padding
		t.Fatal(err)
	}
	// the session waits for frames; an idle authenticated conn must stay open
	_ = client.SetReadDeadline(time.Now().Add(4 * timeout))
	_, err := client.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("authenticated idle session was cut: %v", err)
	}
}

// A stream that is opened but never sends its destination is closed at the
// handshake deadline instead of holding its goroutine forever.
func TestAnyTLSStreamDestinationDeadline(t *testing.T) {
	timeout := 200 * time.Millisecond
	shortHandshakeTimeout(t, timeout)
	client := serveAnyTLSOnce(t)
	hash := sha256.Sum256([]byte("password"))
	req := append(hash[:], 0, 0) // no padding
	settings := []byte("v=2\nclient=test\npadding-md5=" + padding.NewPaddingFactory(padding.DefaultPaddingScheme).Md5)
	req = append(req, frameBytes(4, 0, settings)...) // cmdSettings
	req = append(req, frameBytes(1, 1, nil)...)      // cmdSYN, stream 1, no destination
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hdr [7]byte
	for {
		if _, err := io.ReadFull(client, hdr[:]); err != nil {
			t.Fatalf("stream without a destination was not closed: %v", err)
		}
		data := make([]byte, binary.BigEndian.Uint16(hdr[5:7]))
		if _, err := io.ReadFull(client, data); err != nil {
			t.Fatal(err)
		}
		if hdr[0] == 3 && binary.BigEndian.Uint32(hdr[1:5]) == 1 { // cmdFIN for stream 1
			return
		}
	}
}

func frameBytes(cmd byte, sid uint32, data []byte) []byte {
	b := make([]byte, 7+len(data))
	b[0] = cmd
	binary.BigEndian.PutUint32(b[1:5], sid)
	binary.BigEndian.PutUint16(b[5:7], uint16(len(data)))
	copy(b[7:], data)
	return b
}
