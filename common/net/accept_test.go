package net

import (
	"errors"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestAcceptBackoffStopsOnClosedListener(t *testing.T) {
	var b AcceptBackoff
	if b.Retry(&net.OpError{Op: "accept", Err: net.ErrClosed}, nil) {
		t.Fatal("retried a closed listener")
	}
}

func TestAcceptBackoffGrowsAndResets(t *testing.T) {
	var b AcceptBackoff
	err := &net.OpError{Op: "accept", Err: os.NewSyscallError("accept", syscall.Errno(12))}
	for _, want := range []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond} {
		if !b.Retry(err, nil) {
			t.Fatal("gave up on a non-closed error")
		}
		if b.delay != want {
			t.Fatalf("delay %v, want %v", b.delay, want)
		}
	}
	b.delay = 800 * time.Millisecond
	done := make(chan struct{})
	close(done)
	if b.Retry(err, done) {
		t.Fatal("retried after done was closed")
	}
	if b.delay != time.Second {
		t.Fatalf("delay %v, want the 1s cap", b.delay)
	}
	b.Reset()
	if b.delay != 0 {
		t.Fatalf("delay %v after Reset", b.delay)
	}
}

type scriptedListener struct {
	net.Listener
	errs  []error
	calls atomic.Int32
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	i := int(l.calls.Add(1)) - 1
	if i < len(l.errs) {
		return nil, l.errs[i]
	}
	return nil, net.ErrClosed
}

func TestServeAcceptRetriesUntilClosed(t *testing.T) {
	l := &scriptedListener{errs: []error{
		errors.New("no buffer space"),
		&net.OpError{Op: "accept", Err: os.NewSyscallError("socket", syscall.Errno(10024))},
	}}
	done := make(chan struct{})
	go func() {
		ServeAccept(l, func() bool { return false }, func(net.Conn) { t.Error("unexpected connection") })
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeAccept did not return on a closed listener")
	}
	if n := l.calls.Load(); n != 3 {
		t.Fatalf("Accept called %d times, want 3", n)
	}
}

func TestServeAcceptStopsWhenClosed(t *testing.T) {
	l := &scriptedListener{errs: []error{errors.New("listener gone"), errors.New("listener gone")}}
	done := make(chan struct{})
	go func() {
		ServeAccept(l, func() bool { return true }, func(net.Conn) {})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ServeAccept kept retrying after closed reported true")
	}
	if n := l.calls.Load(); n != 1 {
		t.Fatalf("Accept called %d times, want 1", n)
	}
}

func TestServeAcceptHandsOverConnections(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handled := make(chan net.Conn, 1)
	done := make(chan struct{})
	go func() {
		ServeAccept(raw, func() bool { return false }, func(c net.Conn) { handled <- c })
		close(done)
	}()
	c, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case s := <-handled:
		s.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("connection not handed over")
	}
	raw.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeAccept did not return after the listener closed")
	}
}
