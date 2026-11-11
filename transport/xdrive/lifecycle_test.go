package xdrive

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestDeadlineInterruptsPendingRead(t *testing.T) {
	c, s, cleanup := pair(t)
	defer cleanup()
	result := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); result <- err }()
	time.Sleep(20 * time.Millisecond)
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not interrupt pending Read")
	}
	c.SetReadDeadline(time.Time{})
	if _, err := s.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	expectRead(t, c, "x")
}

type stalledStorage struct {
	Storage
	started chan struct{}
}

func (s *stalledStorage) Put(ctx context.Context, name string, b []byte) error {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}
func TestWriteBackpressureAndCancellation(t *testing.T) {
	base, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &stalledStorage{Storage: base, started: make(chan struct{}, 1)}
	p := paramsFromConfig(&Config{SegmentBytes: 8, Concurrency: 1})
	c := newConn(ctx, store, "up", "down", p, nil)
	defer c.Close()
	result := make(chan error, 1)
	go func() { _, err := c.Write(make([]byte, 1024)); result <- err }()
	<-store.started
	c.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Write ignored backpressure deadline")
	}
	cancel()
}
func TestCloseListenerAndClient(t *testing.T) {
	cfg := *settings(t.TempDir())
	l, err := Listen(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := l.Accept(); result <- err }()
	l.Close()
	if err := <-result; !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	c, err := NewClient(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := c.Dial(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
func TestLocalWindowsTraversalRejected(t *testing.T) {
	s, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{`..\escape`, `folder\..\..\escape`, `a:stream`} {
		if err := s.Put(context.Background(), name, nil); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}
func TestRejectInvalidSessionAnnouncements(t *testing.T) {
	for _, name := range []string{"123-../escape", "123-not-a-session", "123-0000000000000000000000000000000z"} {
		if _, _, ok := parseAnnounce(name); ok {
			t.Fatalf("accepted %q", name)
		}
	}
}

func TestParameterCapsDoNotOverflow32Bit(t *testing.T) {
	p := paramsFromConfig(&Config{SegmentBytes: ^uint32(0), Concurrency: ^uint32(0)})
	if p.segmentBytes != maxSegmentBytes || p.concurrency != maxConcurrency {
		t.Fatalf("invalid parameter caps: %+v", p)
	}
}
