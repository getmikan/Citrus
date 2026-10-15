package session

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"
)

func newTestPadding() *atomic.Pointer[padding.PaddingFactory] {
	p := new(atomic.Pointer[padding.PaddingFactory])
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, p)
	return p
}

// TestCreateStreamWhileServerClosesSession opens streams while the server
// tears the session down from another goroutine as soon as each stream
// arrives (as a revoked user's session is). The client session then closes
// its streams from recvLoop while CreateStream is still returning one; under
// -race this used to report the stream's dieHook being written by
// CreateStream and read by closeLocally.
func TestCreateStreamWhileServerClosesSession(t *testing.T) {
	pad := newTestPadding()
	var servers sync.WaitGroup
	defer servers.Wait()

	dialOut := func(ctx context.Context) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		servers.Add(1)
		go func() {
			defer servers.Done()
			var server *Session
			server = NewServerSession(serverConn, func(stream *Stream) {
				go server.Close()
			}, pad)
			server.Run()
			server.Close()
		}()
		return clientConn, nil
	}

	for _, disableReuse := range []bool{false, true} {
		client := NewClient(context.Background(), dialOut, pad, "test", time.Minute, time.Minute, 0, disableReuse)
		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 50; i++ {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					stream, err := client.CreateStream(ctx)
					cancel()
					if err != nil {
						continue
					}
					_, _ = stream.Write([]byte("ping"))
					_ = stream.Close()
				}
			}()
		}
		wg.Wait()
		_ = client.Close()
	}
}

// TestCreateStreamWhileClientCloses closes the client while streams are being
// created and closed on its sessions.
func TestCreateStreamWhileClientCloses(t *testing.T) {
	pad := newTestPadding()
	var servers sync.WaitGroup
	defer servers.Wait()

	dialOut := func(ctx context.Context) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		servers.Add(1)
		go func() {
			defer servers.Done()
			server := NewServerSession(serverConn, func(stream *Stream) {
				_ = stream.HandshakeSuccess()
				_ = stream.Close()
			}, pad)
			server.Run()
			server.Close()
		}()
		return clientConn, nil
	}

	for i := 0; i < 20; i++ {
		client := NewClient(context.Background(), dialOut, pad, "test", time.Minute, time.Minute, 0, false)
		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					stream, err := client.CreateStream(ctx)
					cancel()
					if err != nil {
						return
					}
					_ = stream.Close()
				}
			}()
		}
		time.Sleep(time.Millisecond)
		_ = client.Close()
		wg.Wait()
	}
}
