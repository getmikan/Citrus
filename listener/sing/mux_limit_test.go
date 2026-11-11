package sing

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	mux "github.com/metacubex/sing-mux"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// echoTunnel echoes TCP sub-streams until they close and UDP packets back to
// their sender.
type echoTunnel struct{}

func (echoTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	_, _ = io.Copy(conn, conn)
	_ = conn.Close()
}

func (echoTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	_, _ = packet.WriteBack(packet.Data(), metadata.UDPAddr())
	packet.Drop()
}

func (echoTunnel) NatTable() C.NatTable { return nil }

// pipeDialer connects the sing-mux client to the handler over net.Pipe and
// counts the connections.
type pipeDialer struct {
	h     *ListenerHandler
	dials atomic.Int32
}

func (d *pipeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	client, server := net.Pipe()
	go func() {
		_ = d.h.NewConnection(context.Background(), server, M.Metadata{
			Source:      M.ParseSocksaddr("192.0.2.1:40000"),
			Destination: destination,
		})
		_ = server.Close()
	}()
	return client, nil
}

func (d *pipeDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

type muxLimitTest struct {
	t       *testing.T
	h       *ListenerHandler
	dialer  *pipeDialer
	client  *mux.Client
	streams atomic.Pointer[muxStreams] // the counter of the (one) connection
}

func newMuxLimitTest(t *testing.T, protocol string, max int) *muxLimitTest {
	t.Helper()
	h, err := NewListenerHandler(ListenerConfig{
		Tunnel:    echoTunnel{},
		Type:      C.SHADOWSOCKS,
		MuxOption: MuxOption{MaxStreams: max},
	})
	if err != nil {
		t.Fatal(err)
	}
	x := &muxLimitTest{t: t, h: h}
	// the service of the handler, recording the counter of the connection
	h.muxService, err = mux.NewService(mux.ServiceOptions{
		NewStreamContext: func(ctx context.Context, conn net.Conn) context.Context {
			if s, ok := ctx.Value(muxStreamsKey{}).(*muxStreams); ok {
				x.streams.Store(s)
			}
			return h.newMuxStreamContext(ctx, conn)
		},
		Logger:  muxLogger{log.SingInfoToDebugLogger},
		Handler: h,
	})
	if err != nil {
		t.Fatal(err)
	}
	x.dialer = &pipeDialer{h: h}
	x.client, err = mux.NewClient(mux.Options{
		Dialer:         x.dialer,
		Protocol:       protocol,
		MaxConnections: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.client.Close() })
	return x
}

func (x *muxLimitTest) dial(network string) net.Conn {
	x.t.Helper()
	conn, err := x.client.DialContext(context.Background(), network, M.ParseSocksaddr("198.51.100.1:443"))
	if err != nil {
		x.t.Fatal(err)
	}
	return conn
}

func echo(conn net.Conn, msg string, timeout time.Duration) error {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte(msg)); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if string(got) != msg {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// open returns the number of open sub-streams counted on the connection.
func (x *muxLimitTest) open() int32 {
	if s := x.streams.Load(); s != nil {
		return s.open.Load()
	}
	return 0
}

func (x *muxLimitTest) waitOpen(want int32) {
	x.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for x.open() != want {
		if time.Now().After(deadline) {
			x.t.Fatalf("%d sub-streams counted, want %d", x.open(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// the sub-stream must not echo: refused, the server closed it when accepted
func (x *muxLimitTest) mustBeRefused(network string) {
	x.t.Helper()
	conn := x.dial(network)
	defer conn.Close()
	// smux drops the FIN of a sub-stream refused before the client registers
	// it, so a refused smux sub-stream may just stay silent
	if err := echo(conn, "over", 2*time.Second); err == nil {
		x.t.Fatalf("%s sub-stream over the cap was not refused", network)
	}
}

var muxLimitProtocols = []string{"h2mux", "smux", "yamux"}

// One sing-mux connection used to get a goroutine for every sub-stream its
// client opened, with no limit; beyond the cap a sub-stream is now refused
// while the connection and its other sub-streams keep working, and a slot is
// given back when its sub-stream closes.
func TestMuxStreamCap(t *testing.T) {
	const max = 4
	for _, protocol := range muxLimitProtocols {
		t.Run(protocol, func(t *testing.T) {
			x := newMuxLimitTest(t, protocol, max)

			// TCP and UDP sub-streams share the cap
			held := make([]net.Conn, 0, max)
			for i := 0; i < max; i++ {
				network := N.NetworkTCP
				if i%2 == 1 {
					network = N.NetworkUDP
				}
				conn := x.dial(network)
				defer conn.Close()
				if err := echo(conn, "hello", 5*time.Second); err != nil {
					t.Fatalf("%s sub-stream %d: %v", network, i, err)
				}
				held = append(held, conn)
			}
			x.waitOpen(max)

			x.mustBeRefused(N.NetworkTCP)
			x.mustBeRefused(N.NetworkUDP)

			// the held sub-streams still work
			for i, conn := range held {
				if err := echo(conn, "again", 5*time.Second); err != nil {
					t.Fatalf("held sub-stream %d after the refusals: %v", i, err)
				}
			}
			if n := x.dialer.dials.Load(); n != 1 {
				t.Fatalf("%d mux connections, want 1", n)
			}

			// closing a sub-stream gives its slot back
			_ = held[0].Close()
			_ = held[1].Close()
			x.waitOpen(max - 2)
			for i := 0; i < 2; i++ {
				conn := x.dial(N.NetworkTCP)
				defer conn.Close()
				if err := echo(conn, "reuse", 5*time.Second); err != nil {
					t.Fatalf("sub-stream after a close: %v", err)
				}
			}
			x.waitOpen(max)
			x.mustBeRefused(N.NetworkTCP)
			if n := x.dialer.dials.Load(); n != 1 {
				t.Fatalf("%d mux connections, want 1", n)
			}
		})
	}
}

// A sub-stream that never sends its request header holds a slot only until
// the request timeout, so silent sub-streams cannot keep the cap filled.
func TestMuxStreamCapSilentStreams(t *testing.T) {
	const max = 3
	for _, protocol := range muxLimitProtocols {
		t.Run(protocol, func(t *testing.T) {
			x := newMuxLimitTest(t, protocol, max)
			x.h.muxRequestTimeout = 300 * time.Millisecond
			x.h.muxReleaseGrace = 100 * time.Millisecond

			// a sing-mux client sends the header with the first write, so
			// these sub-streams are opened but stay silent
			for i := 0; i < max; i++ {
				conn := x.dial(N.NetworkTCP)
				defer conn.Close()
			}
			x.waitOpen(max)
			x.mustBeRefused(N.NetworkTCP)

			// the slots come back after the timeout
			x.waitOpen(0)
			conn := x.dial(N.NetworkTCP)
			defer conn.Close()
			if err := echo(conn, "late", 5*time.Second); err != nil {
				t.Fatalf("sub-stream after the silent ones expired: %v", err)
			}
		})
	}
}

func TestMuxStreamsDefault(t *testing.T) {
	ctx := withMuxStreams(context.Background(), 0, M.Socksaddr{})
	s := ctx.Value(muxStreamsKey{}).(*muxStreams)
	if s.max != DefaultMuxMaxStreams {
		t.Fatalf("max %d, want %d", s.max, DefaultMuxMaxStreams)
	}
	// a nested mux connection shares the counter of its parent
	if nested := withMuxStreams(ctx, 7, M.Socksaddr{}); nested.Value(muxStreamsKey{}).(*muxStreams) != s {
		t.Fatal("a nested mux connection got a counter of its own")
	}
}

func TestMuxStreamsMaxBounds(t *testing.T) {
	for _, tc := range []struct {
		max  int
		want int32
	}{
		{-5, DefaultMuxMaxStreams},
		{1 << 40, 1<<31 - 1}, // would wrap negative and refuse every sub-stream
	} {
		s := withMuxStreams(context.Background(), tc.max, M.Socksaddr{}).Value(muxStreamsKey{}).(*muxStreams)
		if s.max != tc.want {
			t.Fatalf("max-streams %d: max %d, want %d", tc.max, s.max, tc.want)
		}
		if !s.acquire() {
			t.Fatalf("max-streams %d: the first sub-stream was refused", tc.max)
		}
	}
}
