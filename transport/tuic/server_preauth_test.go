package tuic

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbounduser"
	"github.com/metacubex/mihomo/transport/socks5"
	v5 "github.com/metacubex/mihomo/transport/tuic/v5"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

const preAuthTestPassword = "preauth-password"

type preAuthTestServer struct {
	addr     string
	user     uuid.UUID
	tcpCount atomic.Int64
	udpCount atomic.Int64
}

func startPreAuthTestServer(t *testing.T) *preAuthTestServer {
	t.Helper()
	certPEM, keyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	require.NoError(t, err)

	ts := &preAuthTestServer{user: uuid.Must(uuid.NewV4())}
	users, err := inbounduser.New(v5.UserKey, []C.InboundUser{{Name: ts.user.String(), Secret: preAuthTestPassword}})
	require.NoError(t, err)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	server, err := NewServer(&ServerOption{
		HandleTcpFn: func(conn net.Conn, addr socks5.Addr, additions ...inbound.Addition) error {
			ts.tcpCount.Add(1)
			_ = conn.Close()
			return nil
		},
		HandleUdpFn: func(addr socks5.Addr, packet C.UDPPacket, additions ...inbound.Addition) error {
			ts.udpCount.Add(1)
			return nil
		},
		TlsConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h3"},
		},
		QuicConfig: &quic.Config{
			MaxIncomingStreams:    2048,
			MaxIncomingUniStreams: 2048,
			EnableDatagrams:       true,
			MaxIdleTimeout:        30 * time.Second,
		},
		Users:                 users,
		AuthenticationTimeout: 30 * time.Second, // the test authenticates by itself
		MaxUdpRelayPacketSize: 1200,
	}, pc)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve() }()

	ts.addr = pc.LocalAddr().String()
	return ts
}

func (ts *preAuthTestServer) dial(t *testing.T) *quic.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, ts.addr, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}, &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 30 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	return conn
}

func (ts *preAuthTestServer) authenticate(t *testing.T, conn *quic.Conn) {
	t.Helper()
	token, err := v5.GenToken(conn.ConnectionState(), ts.user, preAuthTestPassword)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, v5.NewAuthenticate(ts.user, token).WriteTo(&buf))
	stream, err := conn.OpenUniStream()
	require.NoError(t, err)
	_, err = stream.Write(buf.Bytes())
	require.NoError(t, err)
	closeUniStream(stream)
}

// closeUniStream sends the FIN of a unidirectional stream. The server stops
// reading (STOP_SENDING) as soon as it has parsed the command, or drops a
// packet over the budget, and that may reach the client before it closes:
// then Close reports the canceled stream, which the TUIC client ignores too.
func closeUniStream(stream *quic.SendStream) {
	_ = stream.Close()
}

func preAuthTestAddress() v5.Address {
	return v5.NewAddressAddrPort(netip.MustParseAddrPort("127.0.0.1:53"))
}

// settledGoroutines polls the goroutine count until it has stayed within
// baseline+limit for a quarter of a second and returns it; at the deadline it
// returns the count then.
//
// One sample over the limit proves nothing: the server spawns a handler for
// every unidirectional stream before it reads the stream's header (only then
// is the stream known to carry a packet that needs a budget slot), and on a
// loaded machine hundreds of those are created before the scheduler runs any
// of them; each then exits at once, as the budget is full. Handlers that park
// until the authentication outcome stay until AuthenticationTimeout, well past
// the deadline, so a missing budget still fails.
func settledGoroutines(baseline, limit int, within time.Duration) int {
	const stableSamples = 10 // 25ms apart
	deadline := time.Now().Add(within)
	stable := 0
	for {
		time.Sleep(25 * time.Millisecond)
		n := runtime.NumGoroutine()
		if n-baseline <= limit {
			stable++
		} else {
			stable = 0
		}
		if stable >= stableSamples || time.Now().After(deadline) {
			return n
		}
	}
}

// An unauthenticated client must not make the server park one goroutine per
// datagram or stream until the authentication timeout.
func TestServerPreAuthBudget(t *testing.T) {
	ts := startPreAuthTestServer(t)
	conn := ts.dial(t)
	time.Sleep(100 * time.Millisecond) // let the server settle the connection
	baseline := runtime.NumGoroutine()

	const datagrams = 2000
	var buf bytes.Buffer
	for i := 0; i < datagrams; i++ {
		buf.Reset()
		payload := []byte("x")
		packet := v5.NewPacket(1, uint16(i), 1, 0, uint16(len(payload)), preAuthTestAddress(), payload)
		require.NoError(t, packet.WriteTo(&buf))
		require.NoError(t, conn.SendDatagram(append([]byte(nil), buf.Bytes()...)))
		if i%64 == 63 {
			time.Sleep(time.Millisecond) // do not overrun the receive queue
		}
	}

	const streams = 500
	connectHeader := func() []byte {
		var b bytes.Buffer
		require.NoError(t, v5.NewConnect(preAuthTestAddress()).WriteTo(&b))
		return b.Bytes()
	}()
	for i := 0; i < streams; i++ {
		stream, err := conn.OpenStream()
		require.NoError(t, err)
		_, err = stream.Write(connectHeader)
		require.NoError(t, err)
	}

	// UDP-over-stream packets, opened before the authenticate stream (the
	// client authenticates concurrently with its first packets)
	const uniStreams = 500
	uniPackets := make([]*quic.SendStream, 0, uniStreams)
	for i := 0; i < uniStreams; i++ {
		buf.Reset()
		payload := []byte("z")
		packet := v5.NewPacket(3, uint16(i), 1, 0, uint16(len(payload)), preAuthTestAddress(), payload)
		require.NoError(t, packet.WriteTo(&buf))
		stream, err := conn.OpenUniStream()
		require.NoError(t, err)
		_, err = stream.Write(buf.Bytes())
		require.NoError(t, err)
		// left open: Close would hide the STOP_SENDING awaited below
		uniPackets = append(uniPackets, stream)
	}

	// The server drops a packet over the budget and stops reading its stream
	// (STOP_SENDING). Once the client has seen that for every packet beyond
	// the budget, the server has handled all of them, so none is left over to
	// be handled, without a budget, after the authentication. (The datagrams,
	// sent before, are taken by a loop of their own that never waits.)
	dropped := func() int {
		n := 0
		for _, stream := range uniPackets {
			if context.Cause(stream.Context()) != nil {
				n++
			}
		}
		return n
	}
	require.Eventuallyf(t, func() bool { return dropped() >= uniStreams-preAuthMaxUniStreams }, 10*time.Second, 10*time.Millisecond,
		"packet streams dropped before authentication: %d", dropped())

	// before the fix: one parked goroutine per datagram and per stream
	limit := preAuthMaxDatagrams + preAuthMaxStreams + preAuthMaxUniStreams + 100
	// the deadline is well within the AuthenticationTimeout
	n := settledGoroutines(baseline, limit, 10*time.Second)
	require.LessOrEqualf(t, n-baseline, limit, "goroutines grew by %d before authentication", n-baseline)

	// the queued streams are served once the client authenticates
	ts.authenticate(t, conn)
	require.Eventually(t, func() bool { return ts.tcpCount.Load() == streams }, 10*time.Second, 20*time.Millisecond,
		"tcp relays handled: %d", ts.tcpCount.Load())
	require.LessOrEqual(t, ts.udpCount.Load(), int64(preAuthMaxDatagrams+preAuthMaxUniStreams))

	// and after authentication datagrams are no longer budgeted
	before := ts.udpCount.Load()
	for i := 0; i < 2*preAuthMaxDatagrams; i++ {
		buf.Reset()
		payload := []byte("y")
		packet := v5.NewPacket(2, uint16(i), 1, 0, uint16(len(payload)), preAuthTestAddress(), payload)
		require.NoError(t, packet.WriteTo(&buf))
		require.NoError(t, conn.SendDatagram(append([]byte(nil), buf.Bytes()...)))
		time.Sleep(time.Millisecond)
	}
	require.Eventually(t, func() bool { return ts.udpCount.Load()-before > preAuthMaxDatagrams }, 5*time.Second, 20*time.Millisecond,
		"datagrams handled after auth: %d", ts.udpCount.Load()-before)
}

// A legit client authenticates first and sends right away; nothing it sends
// before the server has processed the authentication may get lost on streams.
func TestServerPreAuthLegitBurst(t *testing.T) {
	ts := startPreAuthTestServer(t)
	conn := ts.dial(t)
	ts.authenticate(t, conn)

	const streams = 300
	var b bytes.Buffer
	require.NoError(t, v5.NewConnect(preAuthTestAddress()).WriteTo(&b))
	for i := 0; i < streams; i++ {
		stream, err := conn.OpenStream()
		require.NoError(t, err)
		_, err = stream.Write(b.Bytes())
		require.NoError(t, err)
	}
	require.Eventually(t, func() bool { return ts.tcpCount.Load() == streams }, 10*time.Second, 20*time.Millisecond,
		"tcp relays handled: %d", ts.tcpCount.Load())
}
