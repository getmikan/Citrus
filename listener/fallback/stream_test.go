package fallback

import (
	"bytes"
	"io"
	"net"
	"slices"
	"testing"
	"time"
)

func TestRequestPath(t *testing.T) {
	for _, tt := range []struct {
		in   string
		path string
		done bool
	}{
		{"GET /a HTTP/1.1\r\n", "/a", true},
		{"POST /a/b?x=1 HTTP/1.1", "/a/b", true},
		{"GET /a#f HTTP/1.1", "/a", true},
		{"OPTIONS / HTTP/1.1", "/", true},
		{"GET /partial", "", false},
		{"GET ", "", false},
		{"GE", "", false},
		{"GET /a\r\n", "", true}, // no version
		{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "", true},
		{"get /a HTTP/1.1", "", true},
		{" /a HTTP/1.1", "", true},
		{"\x00\x01", "", true},
		{"VERYLONGMETHODNAMEX /a HTTP/1.1", "", true},
	} {
		path, done := requestPath([]byte(tt.in))
		if path != tt.path || done != tt.done {
			t.Errorf("requestPath(%q) = %q, %v; want %q, %v", tt.in, path, done, tt.path, tt.done)
		}
	}
}

func TestParseDest(t *testing.T) {
	for _, tt := range []struct {
		in, network, address string
	}{
		{"8080", "tcp", "127.0.0.1:8080"},
		{"127.0.0.1:80", "tcp", "127.0.0.1:80"},
		{"[::1]:80", "tcp", "[::1]:80"},
		{"nginx:80", "tcp", "nginx:80"},
		{"/run/nginx.sock", "unix", "/run/nginx.sock"},
		{"@nginx", "unix", "@nginx"},
		{`unix:C:\nginx.sock`, "unix", `C:\nginx.sock`},
	} {
		network, address, err := parseDest(tt.in)
		if err != nil || network != tt.network || address != tt.address {
			t.Errorf("parseDest(%q) = %q, %q, %v; want %q, %q", tt.in, network, address, err, tt.network, tt.address)
		}
	}
	for _, in := range []string{"", "0", "70000", "localhost", ":80", "host:x", "host:0", "unix:"} {
		if _, _, err := parseDest(in); err == nil {
			t.Errorf("parseDest(%q) accepted", in)
		}
	}
}

// match picks as Xray-core does: by name (exact, else the longest name the SNI
// contains), then ALPN, then path, with the gaps of a name filled from the
// fallbacks without one.
func TestMatchPrecedence(t *testing.T) {
	s, err := NewStreams("test", []Target{
		{Dest: "1"},
		{Path: "/p", Dest: "2"},
		{ALPN: "h2", Dest: "3"},
		{ALPN: "h2", Path: "/p", Dest: "4"},
		{Name: "example.com", Dest: "5"},
		{Name: "b.example.com", Dest: "6"},
		{Name: "A.example.com.", Path: "/q", Dest: "7"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		sni, alpn, path, want string
	}{
		{"", "", "", "1"},
		{"", "", "/p", "2"},
		{"", "h2", "", "3"},
		{"", "h2", "/p", "4"},
		{"", "h2", "/x", "3"},
		{"", "http/1.1", "/p", "2"},
		{"other.org", "", "", "1"},
		{"www.example.com", "", "", "5"},   // a name takes the names that contain it
		{"notexample.com", "", "", "5"},    // as a substring, as in Xray
		{"x.b.example.com", "", "", "6"},   // the longest one
		{"www.example.com", "", "/p", "2"}, // a name inherits the paths of no name
		{"www.example.com", "h2", "/p", "4"},
		{"www.example.com", "h2", "", "5"}, // and its own entry comes before the ALPN of no name
		{"A.Example.COM.", "", "/q", "7"},  // case and the root dot
		{"a.example.com", "", "", "1"},     // the gaps of a name come from no name, not from a shorter name
	} {
		got := s.match(tt.sni, tt.alpn, tt.path)
		if got == nil || got.Dest != tt.want {
			t.Errorf("match(%q, %q, %q) = %+v, want dest %s", tt.sni, tt.alpn, tt.path, got, tt.want)
		}
	}
	s, _ = NewStreams("test", []Target{{Name: "a.example.com", Dest: "1"}})
	for _, sni := range []string{"b.example.com", ""} {
		if got := s.match(sni, "", ""); got != nil {
			t.Errorf("match(%q) without a default = %+v, want none", sni, got)
		}
	}
	s, _ = NewStreams("test", []Target{{Dest: "1"}, {Name: "a.example.com", ALPN: "h2", Dest: "2"}})
	if got := s.match("a.example.com", "http/1.1", ""); got == nil || got.Dest != "1" {
		t.Errorf("a name without the ALPN = %+v, want the default", got)
	}
}

// The Xray-core fallbacks of the review: a ws path, served by another
// inbound, and a site by SNI. The ws client with that SNI reaches the path.
func TestMatchXrayPathUnderName(t *testing.T) {
	s, err := NewStreams("test", []Target{
		{Dest: "80"},
		{Path: "/ws", Dest: "127.0.0.1:10001"},
		{Name: "blog.example.com", Dest: "8082"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.match("blog.example.com", "", "/ws"); got == nil || got.Dest != "127.0.0.1:10001" {
		t.Errorf("ws under the blog name = %+v, want the ws inbound", got)
	}
	if got := s.match("blog.example.com", "", "/"); got == nil || got.Dest != "8082" {
		t.Errorf("blog = %+v, want 8082", got)
	}
}

func TestNewStreamsNames(t *testing.T) {
	s, err := NewStreams("test", []Target{{Name: "Blog.Example.com.", Dest: "1"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.match("blog.example.com", "", ""); got == nil {
		t.Error("a name with the root dot never matches")
	}
	for _, name := range []string{"*.example.com", "a.*.com"} {
		if _, err := NewStreams("test", []Target{{Name: name, Dest: "1"}}); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	// the same name once the dot is trimmed
	if _, err := NewStreams("test", []Target{{Name: "a.com", Dest: "1"}, {Name: "a.com.", Dest: "2"}}); err == nil {
		t.Error("duplicate name accepted")
	}
}

func TestWarnNow(t *testing.T) {
	var s Streams
	now := time.Now()
	if !s.warnNow(now) {
		t.Fatal("first failure not warned")
	}
	if s.warnNow(now.Add(warnInterval - time.Second)) {
		t.Fatal("second failure within the interval warned")
	}
	if !s.warnNow(now.Add(warnInterval)) {
		t.Fatal("failure after the interval not warned")
	}
}

func TestNewStreamsEmpty(t *testing.T) {
	if s, err := NewStreams("test", nil); s != nil || err != nil {
		t.Fatalf("NewStreams(nil) = %v, %v", s, err)
	}
}

func TestNextProtos(t *testing.T) {
	if got := NextProtos([]Target{{Dest: "1"}, {Path: "/p", Dest: "2"}}); got != nil {
		t.Errorf("no ALPN: %q, want nil", got)
	}
	if got := NextProtos([]Target{{ALPN: "h2", Dest: "1"}, {ALPN: "h2", Path: "/p", Dest: "2"}}); !slices.Equal(got, []string{"h2", "http/1.1"}) {
		t.Errorf("h2: %q", got)
	}
	if got := NextProtos([]Target{{ALPN: "http/1.1", Dest: "1"}, {ALPN: "h2", Dest: "2"}}); !slices.Equal(got, []string{"http/1.1", "h2"}) {
		t.Errorf("http/1.1, h2: %q", got)
	}
}

// pipePair is a client and a server end of a TCP connection on loopback.
func pipePair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err = net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err = l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

// Sniff of the protocol's own stream reads no more than classify asks for and
// puts it all back, across reads of a few bytes.
func TestSniffOwn(t *testing.T) {
	s, _ := NewStreams("test", []Target{{Dest: "1"}})
	client, server := pipePair(t)
	go func() {
		for _, part := range []string{"ab", "cd", "efgh-rest"} {
			_, _ = io.WriteString(client, part)
			time.Sleep(20 * time.Millisecond)
		}
	}()
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn, ok := s.Sniff(server, 8, func(b []byte) Verdict {
		if len(b) < 8 {
			return More
		}
		return Own
	})
	if !ok {
		t.Fatal("own stream not returned")
	}
	got := make([]byte, len("abcdefgh-rest"))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "abcdefgh-rest" {
		t.Fatalf("read back %q, %v", got, err)
	}
}

// Sniff relays another stream, with the bytes it read and those of the
// request line it waits for, to the target of its path.
func TestSniffOtherWaitsForThePath(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	s, err := NewStreams("test", []Target{{Path: "/p", Dest: backend.Addr().String()}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	client, server := pipePair(t)
	request := "GET /p HTTP/1.1\r\n\r\n"
	go func() {
		_, _ = io.WriteString(client, request[:1])
		time.Sleep(20 * time.Millisecond)
		_, _ = io.WriteString(client, request[1:5])
		time.Sleep(20 * time.Millisecond)
		_, _ = io.WriteString(client, request[5:])
	}()
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	done := make(chan bool)
	go func() {
		_, ok := s.Sniff(server, 4, func(b []byte) Verdict { return Other })
		done <- ok
	}()
	c, err := backend.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(request))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, []byte(request)) {
		t.Fatalf("backend got %q, %v", got, err)
	}
	// the relay outlives the sniff deadline: the deadline was lifted
	time.Sleep(1500 * time.Millisecond)
	_, _ = io.WriteString(c, "pong")
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	pong := make([]byte, 4)
	if _, err := io.ReadFull(client, pong); err != nil || string(pong) != "pong" {
		t.Fatalf("client got %q, %v", pong, err)
	}
	c.Close()
	client.Close()
	if <-done {
		t.Fatal("Sniff returned another stream as own")
	}
}

// A stream that stops inside what could be the protocol's header is closed
// at the deadline and reaches no fallback.
func TestSniffStallCloses(t *testing.T) {
	s, _ := NewStreams("test", []Target{{Dest: "1"}})
	client, server := pipePair(t)
	_, _ = io.WriteString(client, "ab")
	_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, ok := s.Sniff(server, 8, func(b []byte) Verdict { return More }); ok {
		t.Fatal("stalled stream returned as own")
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("stalled stream left open")
	}
}

// The relays of a Streams have no caps, as in Xray-core: more than
// MaxPerSource from one address are served. Close still ends them.
func TestServeHasNoCaps(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	s, err := NewStreams("test", []Target{{Dest: backend.Addr().String()}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	clients := make([]net.Conn, MaxPerSource+1)
	for i := range clients {
		var server net.Conn
		clients[i], server = pipePair(t)
		go s.serve(server, []byte("x"))
		c, err := backend.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
			t.Fatalf("relay %d: %v", i, err)
		}
	}
	// Close ends the open relays
	s.Close()
	for i, client := range clients {
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadAll(client); err != nil {
			t.Fatalf("relay %d not closed: %v", i, err)
		}
	}
}
