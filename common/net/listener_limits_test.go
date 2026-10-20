package net

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func guardedTestListener(t *testing.T, limit int, timeout time.Duration, handle func(context.Context, net.Conn) (net.Conn, error)) *handleContextListener {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewHandleContextListener(context.Background(), raw, handle, nil).(*handleContextListener)
	l.slots = make(chan struct{}, limit)
	l.timeout = timeout
	l.once.Do(l.init)
	t.Cleanup(func() { l.Close() })
	return l
}
func dialGuarded(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(2 * time.Second))
	return c
}

func TestListenerBoundsPendingHandshakesAndRecoversCapacity(t *testing.T) {
	entered := make(chan struct{}, 4)
	l := guardedTestListener(t, 2, time.Minute, func(ctx context.Context, c net.Conn) (net.Conn, error) {
		entered <- struct{}{}
		var p [1]byte
		_, err := c.Read(p[:])
		return nil, err
	})
	first := dialGuarded(t, l)
	<-entered
	dialGuarded(t, l)
	<-entered
	third := dialGuarded(t, l)
	if _, err := third.Read(make([]byte, 1)); err == nil {
		t.Fatal("over-limit handshake accepted")
	}
	first.Close()
	deadline := time.Now().Add(time.Second)
	for len(l.slots) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("handshake slot leaked")
		}
		time.Sleep(time.Millisecond)
	}
	fourth := dialGuarded(t, l)
	defer fourth.Close()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("released capacity was not usable")
	}
}

func TestListenerHandshakeDeadlineClosesSilentPeer(t *testing.T) {
	finished := make(chan struct{})
	l := guardedTestListener(t, 2, 40*time.Millisecond, func(ctx context.Context, c net.Conn) (net.Conn, error) {
		defer close(finished)
		var p [1]byte
		_, err := c.Read(p[:])
		return nil, err
	})
	c := dialGuarded(t, l)
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("silent peer remained open")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("timed-out handler retained")
	}
}

func TestClassifiedFallbackHasNoHandshakeDeadlineOrSlot(t *testing.T) {
	classified := make(chan struct{}, 2)
	l := guardedTestListener(t, 1, 100*time.Millisecond, func(ctx context.Context, c net.Conn) (net.Conn, error) {
		var p [1]byte
		if _, err := io.ReadFull(c, p[:]); err != nil {
			return nil, err
		}
		HandshakeComplete(c)
		classified <- struct{}{}
		_, err := io.Copy(c, c)
		return nil, err
	})
	for n := 0; n < 2; n++ {
		c := dialGuarded(t, l)
		if _, err := c.Write([]byte("f")); err != nil {
			t.Fatal(err)
		}
		select {
		case <-classified:
		case <-time.After(time.Second):
			t.Fatal("fallback was not classified")
		}
		deadline := time.Now().Add(time.Second)
		for len(l.slots) != 0 {
			if time.Now().After(deadline) {
				t.Fatal("fallback retained handshake slot")
			}
			time.Sleep(time.Millisecond)
		}
		time.Sleep(150 * time.Millisecond)
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		var got [1]byte
		if _, err := io.ReadFull(c, got[:]); err != nil || got[0] != 'x' {
			t.Fatalf("fallback did not outlive handshake: %v", err)
		}
	}
}

func TestAcceptedHandshakeKeepsConnectionContext(t *testing.T) {
	contexts := make(chan context.Context, 1)
	l := guardedTestListener(t, 1, 40*time.Millisecond, func(ctx context.Context, c net.Conn) (net.Conn, error) { contexts <- ctx; return c, nil })
	client := dialGuarded(t, l)
	server, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	ctx := <-contexts
	time.Sleep(80 * time.Millisecond)
	if ctx.Err() != nil {
		t.Fatal("completed handshake cancelled the live connection context")
	}
	written := make(chan error, 1)
	go func() { _, err := server.Write([]byte("x")); written <- err }()
	var got [1]byte
	if _, err := io.ReadFull(client, got[:]); err != nil || got[0] != 'x' {
		t.Fatalf("accepted connection lost: %v", err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	server.Close()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("connection close did not cancel its context")
	}
}

func TestAcceptedHandshakePreservesTCPHalfClose(t *testing.T) {
	contexts := make(chan context.Context, 1)
	l := guardedTestListener(t, 1, time.Second, func(ctx context.Context, c net.Conn) (net.Conn, error) { contexts <- ctx; return c, nil })
	client := dialGuarded(t, l)
	server, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx := <-contexts
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(server)
	if err != nil || string(request) != "request" {
		t.Fatalf("request changed: %q, %v", request, err)
	}
	if _, err := server.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := server.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil || string(response) != "response" {
		t.Fatalf("half-close lost response: %q, %v", response, err)
	}
	if ctx.Err() != nil {
		t.Fatal("half-close cancelled the live connection context")
	}
}

func TestListenerCloseCancelsPendingHandlersAndAccept(t *testing.T) {
	var handlers sync.WaitGroup
	entered := make(chan struct{})
	l := guardedTestListener(t, 1, time.Minute, func(ctx context.Context, c net.Conn) (net.Conn, error) {
		handlers.Add(1)
		defer handlers.Done()
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	dialGuarded(t, l)
	<-entered
	done := make(chan error, 1)
	go func() { _, err := l.Accept(); done <- err }()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept did not stop")
	}
	handlers.Wait()
}
