package session

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	M "github.com/metacubex/sing/common/metadata"
)

// benchPair connects a client and a server session over loopback TCP. The
// server runs handler for every stream after reading its destination and
// reporting the handshake, as the listener does.
func benchPair(b *testing.B, handler func(*Stream)) *Client {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				s := NewServerSession(c, func(stream *Stream) {
					defer stream.Close()
					if _, err := M.SocksaddrSerializer.ReadAddrPort(stream); err != nil {
						return
					}
					if stream.HandshakeSuccess() != nil {
						return
					}
					handler(stream)
				}, newTestPadding())
				s.Run()
				s.Close()
			}()
		}
	}()
	client := NewClient(context.Background(), func(ctx context.Context) (net.Conn, error) {
		return net.Dial("tcp", ln.Addr().String())
	}, newTestPadding(), "bench", 0, 0, 0, false)
	b.Cleanup(func() { client.Close() })
	return client
}

func openBenchStream(b *testing.B, c *Client) net.Conn {
	conn, err := c.CreateStream(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	if err := M.SocksaddrSerializer.WriteAddrPort(conn, M.ParseSocksaddr("10.0.0.1:80")); err != nil {
		b.Fatal(err)
	}
	return conn
}

func BenchmarkServerDownload(b *testing.B) {
	const chunk = 32 * 1024
	start := make(chan int)
	client := benchPair(b, func(s *Stream) {
		data := make([]byte, chunk)
		for n := <-start; n > 0; n-- {
			if _, err := s.Write(data); err != nil {
				return
			}
		}
	})
	conn := openBenchStream(b, client)
	defer conn.Close()
	b.SetBytes(chunk)
	b.ReportAllocs()
	b.ResetTimer()
	start <- b.N
	if _, err := io.CopyN(io.Discard, conn, int64(b.N)*chunk); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkServerUpload(b *testing.B) {
	const chunk = 32 * 1024
	done := make(chan int64)
	client := benchPair(b, func(s *Stream) {
		n, _ := io.Copy(io.Discard, s)
		done <- n
	})
	conn := openBenchStream(b, client)
	data := make([]byte, chunk)
	b.SetBytes(chunk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(data); err != nil {
			b.Fatal(err)
		}
	}
	conn.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		b.Fatal("server did not finish")
	}
}

// BenchmarkStreamOpen measures a request on a reused session: open a stream,
// send the destination and one byte, read one byte back, close.
func BenchmarkStreamOpen(b *testing.B) {
	client := benchPair(b, func(s *Stream) {
		var one [1]byte
		if _, err := io.ReadFull(s, one[:]); err != nil {
			return
		}
		s.Write(one[:])
	})
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var one [1]byte
		for pb.Next() {
			conn := openBenchStream(b, client)
			if _, err := conn.Write(one[:]); err != nil {
				b.Fatal(err)
			}
			if _, err := io.ReadFull(conn, one[:]); err != nil {
				b.Fatal(err)
			}
			conn.Close()
		}
	})
}
