package muxcool

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vmess "github.com/metacubex/sing-vmess"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type echoHandler struct{}

func (echoHandler) NewConnection(_ context.Context, c net.Conn, _ M.Metadata) error {
	defer c.Close()
	_, err := io.Copy(c, c)
	return err
}
func (echoHandler) NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error {
	return errors.New("UDP not used")
}
func (echoHandler) NewError(context.Context, error) {}

func TestConcurrentStreamsAgainstSingMuxServer(t *testing.T) {
	var dials atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := NewClient(func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		dials.Add(1)
		go func() { defer b.Close(); _ = vmess.HandleMuxConnection(ctx, b, M.Metadata{}, echoHandler{}) }()
		return a, nil
	})
	defer c.Close()
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := c.DialContext(ctx, "echo.test:443")
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			want := bytes.Repeat([]byte{byte(i)}, 96*1024)
			written := make(chan error, 1)
			go func() { _, err := conn.Write(want); written <- err }()
			got := make([]byte, len(want))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Error(err)
				return
			}
			if err := <-written; err != nil {
				t.Error(err)
			}
			if !bytes.Equal(got, want) {
				t.Error("corrupted stream")
			}
		}(i)
	}
	wg.Wait()
	if n := dials.Load(); n > maxSessions {
		t.Fatalf("opened %d sessions", n)
	}
}
func TestPendingReadDeadlineAndClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := NewClient(func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { defer b.Close(); _ = vmess.HandleMuxConnection(ctx, b, M.Metadata{}, echoHandler{}) }()
		return a, nil
	})
	defer c.Close()
	conn, err := c.DialContext(ctx, "echo.test:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); done <- err }()
	conn.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("read stuck")
	}
	conn.SetReadDeadline(time.Time{})
	go func() { _, err := conn.Read(make([]byte, 1)); done <- err }()
	c.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close did not unblock read")
	}
}
