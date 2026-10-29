package net

import (
	"net"
	"os"
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
