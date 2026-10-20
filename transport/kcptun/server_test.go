package kcptun

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/smux"
)

func startTestServer(t *testing.T, config Config, handler func(net.Conn)) (*Server, string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(config)
	done := make(chan error, 1)
	go func() { done <- s.Serve(pc, handler) }()
	t.Cleanup(func() {
		pc.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("server retained after packet socket close")
		}
	})
	return s, pc.LocalAddr().String()
}

func testClientSession(t *testing.T, config Config, addr string) *smux.Session {
	t.Helper()
	c := NewClient(config)
	t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mux, err := c.createConn(ctx, func(context.Context) (net.PacketConn, net.Addr, error) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		t.Cleanup(func() { pc.Close() })
		return pc, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addr)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	return mux
}

func TestKCPTunConcurrentSessionsAndStreams(t *testing.T) {
	for _, noComp := range []bool{false, true} {
		t.Run(fmt.Sprint("noComp=", noComp), func(t *testing.T) {
			cfg := Config{Key: "kcptun-concurrency-test-key", NoComp: noComp, Mode: "fast3", SmuxVer: 2}
			_, addr := startTestServer(t, cfg, func(conn net.Conn) { defer conn.Close(); _, _ = io.Copy(conn, conn) })
			var sessions []*smux.Session
			for n := 0; n < 4; n++ {
				sessions = append(sessions, testClientSession(t, cfg, addr))
			}
			var wg sync.WaitGroup
			errors := make(chan error, 12)
			for n := 0; n < 12; n++ {
				wg.Add(1)
				go func(n int) {
					defer wg.Done()
					stream, err := sessions[n%len(sessions)].OpenStream()
					if err != nil {
						errors <- err
						return
					}
					defer stream.Close()
					stream.SetDeadline(time.Now().Add(5 * time.Second))
					data := bytes.Repeat([]byte{byte(n)}, 32<<10)
					if _, err = stream.Write(data); err != nil {
						errors <- err
						return
					}
					got := make([]byte, len(data))
					if _, err = io.ReadFull(stream, got); err != nil {
						errors <- err
						return
					}
					if !bytes.Equal(data, got) {
						errors <- fmt.Errorf("stream %d corrupted", n)
					}
				}(n)
			}
			wg.Wait()
			close(errors)
			for err := range errors {
				t.Error(err)
			}
		})
	}
}

func TestKCPTunStreamLimitFollowsConnectionLifetime(t *testing.T) {
	cfg := Config{Key: "kcptun-stream-limit-test-key", NoComp: true, Mode: "fast3", MaxStreams: 1, SmuxVer: 2}
	accepted := make(chan net.Conn, 4)
	_, addr := startTestServer(t, cfg, func(conn net.Conn) { accepted <- conn })
	mux := testClientSession(t, cfg, addr)
	open := func() *smux.Stream {
		t.Helper()
		c, err := mux.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		return c
	}
	accept := func() net.Conn {
		t.Helper()
		select {
		case c := <-accepted:
			return c
		case <-time.After(3 * time.Second):
			t.Fatal("stream was not accepted")
			return nil
		}
	}
	first := open()
	serverFirst := accept()
	serverFirst.SetDeadline(time.Now().Add(3 * time.Second))
	var p [1]byte
	if _, err := io.ReadFull(serverFirst, p[:]); err != nil {
		t.Fatalf("handler return closed live stream: %v", err)
	}
	second := open()
	if _, err := second.Read(p[:]); err == nil {
		t.Fatal("stream cap bypassed")
	}
	select {
	case c := <-accepted:
		c.Close()
		t.Fatal("over-limit stream reached handler")
	default:
	}
	serverFirst.Close()
	serverFirst.Close()
	first.Close()
	third := open()
	serverThird := accept()
	defer serverThird.Close()
	serverThird.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(serverThird, p[:]); err != nil {
		t.Fatalf("released capacity did not recover: %v", err)
	}
	if _, err := serverThird.Write([]byte("k")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(third, p[:]); err != nil || p[0] != 'k' {
		t.Fatalf("new stream unusable: %v", err)
	}
}

func TestKCPTunSessionLimitRejectsAnotherPeer(t *testing.T) {
	cfg := Config{Key: "kcptun-session-limit-test-key", NoComp: true, Mode: "fast3", MaxSessions: 1, SmuxVer: 2}
	accepted := make(chan net.Conn, 4)
	s, addr := startTestServer(t, cfg, func(conn net.Conn) { accepted <- conn })
	first := testClientSession(t, cfg, addr)
	stream, err := first.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err = stream.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("first session rejected")
	}
	second := testClientSession(t, cfg, addr)
	extra, err := second.OpenStream()
	if err != nil {
		return
	}
	defer extra.Close()
	extra.SetDeadline(time.Now().Add(300 * time.Millisecond))
	extra.Write([]byte("x"))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("session cap bypassed")
	}
	if len(s.sessions) != 1 {
		t.Fatal("session accounting corrupted")
	}
	select {
	case c := <-accepted:
		c.Close()
		t.Fatal("over-limit session reached handler")
	default:
	}
}
