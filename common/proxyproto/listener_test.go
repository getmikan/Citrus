package proxyproto

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type accepted struct {
	conn net.Conn
	err  error
}

// serve starts a proxy protocol listener on loopback and accepts in the
// background.
func serve(t *testing.T, config Config) (string, <-chan accepted) {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	l := NewListener(raw, config)
	t.Cleanup(func() { _ = l.Close() })
	ch := make(chan accepted, 8)
	go func() {
		for {
			c, err := l.Accept()
			ch <- accepted{c, err}
			if err != nil {
				return
			}
		}
	}()
	return raw.Addr().String(), ch
}

func dial(t *testing.T, addr string, data []byte) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	if len(data) > 0 {
		_, err = c.Write(data)
		require.NoError(t, err)
	}
	return c
}

func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := c.Read(make([]byte, 1))
	// EOF, or a reset when the listener closed with the client's bytes unread
	require.Error(t, err)
	assert.False(t, errors.Is(err, os.ErrDeadlineExceeded), "the listener closes the connection")
}

func expectNoConn(t *testing.T, ch <-chan accepted) {
	t.Helper()
	select {
	case a := <-ch:
		if a.conn != nil {
			_ = a.conn.Close()
		}
		t.Fatalf("Accept returned a connection (err %v), want none", a.err)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestListenerV2(t *testing.T) {
	addr, ch := serve(t, Config{})
	hello := []byte("\x16\x03\x01 client hello")
	c := dial(t, addr, append(v2Header(1, 0x11, v2Addrs("203.0.113.7", "192.0.2.1", 51234, 443)), hello...))

	a := <-ch
	require.NoError(t, a.err)
	defer a.conn.Close()
	assert.Equal(t, "203.0.113.7:51234", a.conn.RemoteAddr().String())
	assert.Equal(t, addr, a.conn.LocalAddr().String(), "the local address stays the listener's")
	got := make([]byte, len(hello))
	_, err := io.ReadFull(a.conn, got)
	require.NoError(t, err)
	assert.Equal(t, hello, got, "the stream starts right after the header")

	// the connection still works both ways
	_, err = a.conn.Write([]byte("pong"))
	require.NoError(t, err)
	pong := make([]byte, 4)
	_, err = io.ReadFull(c, pong)
	require.NoError(t, err)
	assert.Equal(t, "pong", string(pong))
}

func TestListenerV1(t *testing.T) {
	addr, ch := serve(t, Config{})
	dial(t, addr, []byte("PROXY TCP6 2001:db8::7 2001:db8::1 51234 443\r\n"))
	a := <-ch
	require.NoError(t, a.err)
	defer a.conn.Close()
	assert.Equal(t, "[2001:db8::7]:51234", a.conn.RemoteAddr().String())
}

func TestListenerV4MappedSource(t *testing.T) {
	addr, ch := serve(t, Config{})
	dial(t, addr, v2Header(1, 0x21, v2Addrs("::ffff:203.0.113.7", "::ffff:192.0.2.1", 51234, 443)))
	a := <-ch
	require.NoError(t, a.err)
	defer a.conn.Close()
	assert.Equal(t, "203.0.113.7:51234", a.conn.RemoteAddr().String())
}

func TestListenerLocalKeepsThePeer(t *testing.T) {
	for name, header := range map[string][]byte{
		"v2 LOCAL":   v2Header(0, 0x00, nil),
		"v1 UNKNOWN": []byte("PROXY UNKNOWN\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			addr, ch := serve(t, Config{})
			c := dial(t, addr, append(header, "data"...))
			a := <-ch
			require.NoError(t, a.err)
			defer a.conn.Close()
			assert.Equal(t, c.LocalAddr().String(), a.conn.RemoteAddr().String())
			got := make([]byte, 4)
			_, err := io.ReadFull(a.conn, got)
			require.NoError(t, err)
			assert.Equal(t, "data", string(got))
		})
	}
}

func TestListenerRejects(t *testing.T) {
	good := v2Header(1, 0x11, v2Addrs("203.0.113.7", "192.0.2.1", 51234, 443))
	tests := map[string][]byte{
		"no header":        []byte("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03abcdefgh"),
		"malformed v1":     []byte("PROXY TCP4 not-an-address 192.0.2.1 1 2\r\n"),
		"malformed v2":     v2Header(1, 0x12, v2Addrs("1.1.1.1", "2.2.2.2", 1, 2)),
		"too long v1 line": append([]byte("PROXY TCP4 "), make([]byte, 200)...),
		"too long v2":      v2Header(1, 0x11, make([]byte, MaxV2Length+1)),
		"truncated header": good[:len(good)-3],
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			addr, ch := serve(t, Config{Timeout: 2 * time.Second})
			c := dial(t, addr, data)
			if name == "truncated header" {
				// the peer hangs up in the middle of the header
				require.NoError(t, c.(*net.TCPConn).CloseWrite())
			}
			expectClosed(t, c)
			expectNoConn(t, ch)
		})
	}
}

func TestListenerSilentPeerTimesOut(t *testing.T) {
	addr, ch := serve(t, Config{Timeout: 200 * time.Millisecond})
	silent := dial(t, addr, nil)
	// a silent peer neither blocks the accept loop nor holds its connection
	c := dial(t, addr, v2Header(1, 0x11, v2Addrs("203.0.113.7", "192.0.2.1", 51234, 443)))
	_ = c
	a := <-ch
	require.NoError(t, a.err)
	defer a.conn.Close()
	assert.Equal(t, "203.0.113.7:51234", a.conn.RemoteAddr().String())
	start := time.Now()
	expectClosed(t, silent)
	assert.Less(t, time.Since(start), 3*time.Second)
	expectNoConn(t, ch)
}

func TestListenerUntrustedPeer(t *testing.T) {
	good := v2Header(1, 0x11, v2Addrs("203.0.113.7", "192.0.2.1", 51234, 443))

	// the peer is on loopback but only 10.0.0.0/8 is trusted
	addr, ch := serve(t, Config{Trusted: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	expectClosed(t, dial(t, addr, good))
	expectNoConn(t, ch)

	// the default is loopback only, so an IPv6 loopback peer is trusted too
	// and an explicit loopback prefix accepts the header
	addr, ch = serve(t, Config{Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	dial(t, addr, good)
	a := <-ch
	require.NoError(t, a.err)
	_ = a.conn.Close()
}

func TestListenerCloseUnblocksAccept(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	l := NewListener(raw, Config{})
	done := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, l.Close())
	select {
	case err := <-done:
		assert.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Accept still blocks after Close")
	}
}
