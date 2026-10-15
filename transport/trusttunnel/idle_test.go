package trusttunnel

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
	xhttp2 "golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// tunnelSinkHandler reads each tunnel until it fails and reports when the
// handler has returned, which is when ServeHTTP releases the user session.
type tunnelSinkHandler struct {
	done chan struct{}
}

func (h *tunnelSinkHandler) NewConnection(_ context.Context, conn net.Conn, _ M.Metadata) error {
	defer close(h.done)
	_, err := io.Copy(io.Discard, conn)
	return err
}

func (h *tunnelSinkHandler) NewPacketConnection(context.Context, network.PacketConn, M.Metadata) error {
	return errors.New("unexpected UDP tunnel")
}

// startIdleTestServer serves TrustTunnel over cleartext HTTP/2 with the ping
// health check shortened to pingAfter and pingTimeout.
func startIdleTestServer(t *testing.T, pingAfter, pingTimeout time.Duration) (string, *tunnelSinkHandler) {
	t.Helper()
	oldAfter, oldTimeout := h2PingAfter, h2PingTimeout
	h2PingAfter, h2PingTimeout = pingAfter, pingTimeout
	t.Cleanup(func() { h2PingAfter, h2PingTimeout = oldAfter, oldTimeout })
	handler := &tunnelSinkHandler{done: make(chan struct{})}
	s := NewService(ServiceOptions{Ctx: context.Background(), Logger: logger.NOP(), Handler: handler})
	s.UpdateUsers(map[string]string{"user": "secret"})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Start(listener, nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return listener.Addr().String(), handler
}

// openTunnel connects as a raw HTTP/2 client, opens one CONNECT tunnel on
// stream 1 and waits for its 200. Frames that the server sends meanwhile
// (SETTINGS, WINDOW_UPDATE) are consumed.
func openTunnel(t *testing.T, address string) (net.Conn, *xhttp2.Framer) {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = io.WriteString(conn, xhttp2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	framer := xhttp2.NewFramer(conn, conn)
	if err = framer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":authority", Value: "example.com:443"},
		{Name: "proxy-authorization", Value: "Basic " + base64.StdEncoding.EncodeToString([]byte("user:secret"))},
	} {
		_ = encoder.WriteField(field)
	}
	if err = framer.WriteHeaders(xhttp2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		switch f := frame.(type) {
		case *xhttp2.SettingsFrame:
			if !f.IsAck() {
				if err = framer.WriteSettingsAck(); err != nil {
					t.Fatal(err)
				}
			}
		case *xhttp2.HeadersFrame:
			if f.StreamID != 1 {
				t.Fatalf("headers on stream %d", f.StreamID)
			}
			fields, err := hpack.NewDecoder(4096, nil).DecodeFull(f.HeaderBlockFragment())
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range fields {
				if field.Name == ":status" && field.Value != "200" {
					t.Fatalf("tunnel status %s", field.Value)
				}
			}
			_ = conn.SetDeadline(time.Time{})
			return conn, framer
		case *xhttp2.GoAwayFrame, *xhttp2.RSTStreamFrame:
			t.Fatalf("server refused the tunnel: %v", frame)
		}
	}
}

// serveFrames reads frames until the conn fails, answering PINGs when ack is
// set; it reports the PINGs that it has seen.
func serveFrames(framer *xhttp2.Framer, ack bool) <-chan int {
	pings := make(chan int, 1)
	go func() {
		count := 0
		defer func() { pings <- count }()
		for {
			frame, err := framer.ReadFrame()
			if err != nil {
				return
			}
			if ping, isPing := frame.(*xhttp2.PingFrame); isPing && !ping.IsAck() {
				count++
				if ack {
					if framer.WritePing(true, ping.Data) != nil {
						return
					}
				}
			}
		}
	}()
	return pings
}

func expectTunnelOpen(t *testing.T, handler *tunnelSinkHandler, period time.Duration) {
	t.Helper()
	select {
	case <-handler.done:
		t.Fatalf("server closed a live tunnel within %v", period)
	case <-time.After(period):
	}
}

func expectTunnelClosed(t *testing.T, handler *tunnelSinkHandler, limit time.Duration) {
	t.Helper()
	select {
	case <-handler.done:
	case <-time.After(limit):
		t.Fatalf("server kept the tunnel of a silent client for %v", limit)
	}
}

// A client that stops reading and writing, as a phone that lost its network
// does, gets a PING it never answers, and the conn is closed together with the
// tunnel and the user session.
func TestTunnelOfSilentClientIsClosed(t *testing.T) {
	address, handler := startIdleTestServer(t, 200*time.Millisecond, 200*time.Millisecond)
	conn, _ := openTunnel(t, address)
	expectTunnelClosed(t, handler, 5*time.Second)
	// The server side of the TCP conn is gone too: whatever was buffered is
	// followed by EOF or a reset rather than more waiting.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := io.Copy(io.Discard, conn)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("server kept the conn of a silent client open")
	}
}

// A live client that answers PINGs keeps an idle tunnel well past the bound.
// The PING timeout is generous, as the answer of a client stalled by a busy
// machine is merely late.
func TestIdleTunnelOfLiveClientSurvives(t *testing.T) {
	address, handler := startIdleTestServer(t, 100*time.Millisecond, time.Second)
	conn, framer := openTunnel(t, address)
	pings := serveFrames(framer, true)
	expectTunnelOpen(t, handler, 1500*time.Millisecond)
	_ = conn.Close()
	if count := <-pings; count == 0 {
		t.Fatal("server never checked the idle conn with a PING")
	}
}

// A client that keeps uploading is not pinged at all, as every DATA frame
// resets the clock, so even a client whose ACKs would be late keeps its tunnel.
//
// The clock is the server's wall clock, so this cannot be synchronized on
// events: the server pings whenever its serve loop goes pingAfter without
// processing a frame, and a stall of the client's write loop or of the server
// (a busy CI runner) counts too. pingAfter is therefore 100 times the upload
// interval, while the upload still lasts long enough (past pingAfter plus
// pingTimeout) for a server that ignored DATA frames to ping, and then close.
func TestBusyUploadTunnelSurvives(t *testing.T) {
	const (
		pingAfter = time.Second
		interval  = 10 * time.Millisecond
	)
	address, handler := startIdleTestServer(t, pingAfter, 500*time.Millisecond)
	conn, framer := openTunnel(t, address)
	pings := serveFrames(framer, false) // never answers a PING
	chunk := make([]byte, 512)
	deadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := framer.WriteData(1, false, chunk); err != nil {
			t.Fatalf("upload failed: %v", err)
		}
		select {
		case <-handler.done:
			t.Fatal("server closed a tunnel that was uploading")
		case <-time.After(interval):
		}
	}
	_ = conn.Close()
	if count := <-pings; count != 0 {
		t.Fatalf("server pinged an uploading client %d times", count)
	}
}
