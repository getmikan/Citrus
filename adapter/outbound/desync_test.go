package outbound

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/loopback"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	"github.com/Nemu-x/desync"
	"github.com/metacubex/sing/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const desyncTestSNI = "www.youtube.test"

func newTestDesync(t *testing.T, option DesyncOption) *Desync {
	t.Helper()
	if option.Name == "" {
		option.Name = "desync-test"
	}
	d, err := NewDesync(option)
	require.NoError(t, err)
	return d
}

func desyncMetadata(addr net.Addr) *C.Metadata {
	ap := addr.(*net.TCPAddr).AddrPort()
	return &C.Metadata{NetWork: C.TCP, DstIP: ap.Addr().Unmap(), DstPort: ap.Port()}
}

// captureClientHello returns the first record of a real crypto/tls
// handshake, which holds the whole ClientHello.
func captureClientHello(t *testing.T) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		defer client.Close()
		_ = tls.Client(client, &tls.Config{ServerName: desyncTestSNI, InsecureSkipVerify: true}).Handshake()
	}()
	require.NoError(t, server.SetReadDeadline(time.Now().Add(3*time.Second)))
	header := make([]byte, 5)
	_, err := io.ReadFull(server, header)
	require.NoError(t, err)
	record := make([]byte, 5+int(binary.BigEndian.Uint16(header[3:])))
	copy(record, header)
	_, err = io.ReadFull(server, record[5:])
	require.NoError(t, err)
	return record
}

// readHelloRecords reads TLS handshake records from r until they carry the
// whole first handshake message, and returns their wire bytes and the
// equivalent single record.
func readHelloRecords(r io.Reader) (wire, joined []byte, records int, err error) {
	var payload []byte
	for {
		header := make([]byte, 5)
		if _, err = io.ReadFull(r, header); err != nil {
			return
		}
		if header[0] != 0x16 {
			return wire, nil, records, errors.New("not a handshake record")
		}
		body := make([]byte, binary.BigEndian.Uint16(header[3:]))
		if _, err = io.ReadFull(r, body); err != nil {
			return
		}
		wire = append(append(wire, header...), body...)
		payload = append(payload, body...)
		records++
		if len(payload) >= 4 && len(payload) >= 4+(int(payload[1])<<16|int(payload[2])<<8|int(payload[3])) {
			joined = append([]byte{0x16, header[1], header[2], byte(len(payload) >> 8), byte(len(payload))}, payload...)
			return
		}
	}
}

// expectedFragments is what the "1+s" cut makes of a single-record hello.
func expectedFragments(t *testing.T, record []byte) []byte {
	t.Helper()
	h, err := desync.ParseHello(record)
	require.NoError(t, err)
	require.Equal(t, desyncTestSNI, h.SNI)
	return desync.FragmentRecord(record, []int{h.SNIOffset + 1})
}

// prefixConn replays bytes already read from a connection.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{desyncTestSNI},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// The outbound dials a local TLS server: the server's raw socket sees the
// ClientHello split into records at the configured position, and the
// handshake still completes.
func TestDesyncTLSHandshakeFragmentsClientHello(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	cert := selfSignedCert(t)

	type result struct {
		wire, joined []byte
		records      int
		err          error
	}
	done := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		wire, joined, records, err := readHelloRecords(c)
		if err == nil {
			s := tls.Server(&prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(wire), c)}, &tls.Config{Certificates: []tls.Certificate{cert}})
			if err = s.Handshake(); err == nil {
				_, err = s.Write([]byte("ok"))
			}
		}
		done <- result{wire, joined, records, err}
	}()

	d := newTestDesync(t, DesyncOption{TLSRec: "1+s"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, desyncMetadata(ln.Addr()))
	require.NoError(t, err)
	defer conn.Close()
	assert.Equal(t, []string{"desync-test"}, []string(conn.Chains()))
	client := tls.Client(conn, &tls.Config{ServerName: desyncTestSNI, InsecureSkipVerify: true})
	require.NoError(t, client.HandshakeContext(ctx))
	got := make([]byte, 2)
	_, err = io.ReadFull(client, got)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(got))

	r := <-done
	require.NoError(t, r.err)
	assert.Equal(t, 2, r.records, "one cut, two records")
	assert.Equal(t, expectedFragments(t, r.joined), r.wire, "the cut is one byte into the server name")
}

// Traffic that does not start with a ClientHello is not touched.
func TestDesyncPassesThroughNonTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	request := []byte("GET / HTTP/1.1\r\nHost: www.youtube.test\r\n\r\n")
	received := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, len(request))
		_, _ = io.ReadFull(c, buf)
		received <- buf
	}()
	d := newTestDesync(t, DesyncOption{TLSRec: "1+s", Split: "2"})
	conn, err := d.DialContext(context.Background(), desyncMetadata(ln.Addr()))
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write(request)
	require.NoError(t, err)
	assert.Equal(t, request, <-received)
}

// The relay must not reach the socket under the transformer for writes:
// neither by unwrapping the writer nor by an upstream cast to the socket
// (splice, sendfile, writev batching). Reads may go to the socket.
func TestDesyncConnHidesSocketFromWriteFastPaths(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}
	}()
	d := newTestDesync(t, DesyncOption{TLSRec: "1+s"})
	conn, err := d.DialContext(context.Background(), desyncMetadata(ln.Addr()))
	require.NoError(t, err)
	defer conn.Close()

	w := N.UnwrapWriter(conn)
	_, isSyscall := w.(syscall.Conn)
	assert.False(t, isSyscall, "the writer unwraps to a socket: %T", w)
	_, isDesync := w.(*desyncConn)
	assert.True(t, isDesync, "the writer unwraps past the transformer: %T", w)
	_, found := N.FindUpstream[*net.TCPConn](conn, nil)
	assert.False(t, found, "FindUpstream reaches the socket")
	_, found = N.FindUpstream[*desync.Conn](conn, nil)
	assert.False(t, found, "FindUpstream reaches the transformer, and NetConn below it")
	_, found = common.Cast[syscall.Conn](conn)
	assert.False(t, found, "common.Cast reaches the socket")

	_, isTCP := N.UnwrapReader(conn).(*net.TCPConn)
	assert.True(t, isTCP, "reads go to the socket directly")
	_, hasCloseWrite := common.Cast[interface{ CloseWrite() error }](conn)
	assert.True(t, hasCloseWrite, "half-close is kept")
}

// A real relay between two TCP sockets, each of which could use splice or
// writev: the first bytes still arrive transformed.
func TestDesyncRelayKeepsTransformer(t *testing.T) {
	record := captureClientHello(t)
	want := expectedFragments(t, record)

	target, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer target.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := target.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, len(want))
		_, _ = io.ReadFull(c, buf)
		got <- buf
	}()

	// the client's side: a TCP connection accepted by an inbound
	inbound, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer inbound.Close()
	app, err := net.Dial("tcp", inbound.Addr().String())
	require.NoError(t, err)
	defer app.Close()
	accepted, err := inbound.Accept()
	require.NoError(t, err)

	d := newTestDesync(t, DesyncOption{TLSRec: "1+s"})
	remote, err := d.DialContext(context.Background(), desyncMetadata(target.Addr()))
	require.NoError(t, err)
	go N.Relay(accepted, remote)

	_, err = app.Write(record)
	require.NoError(t, err)
	assert.Equal(t, want, <-got, "the relay bypassed the transformer")
}

func TestDesyncDialRespectsContext(t *testing.T) {
	d := newTestDesync(t, DesyncOption{TLSRec: "1+s"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := d.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 9})
	assert.ErrorIs(t, err, context.Canceled)

	// cancelled while the dial is in progress: the name lookup blocks
	// until the context ends
	old := resolver.DirectHostResolver
	resolver.DirectHostResolver = blockingResolver{&fixedResolver{}}
	defer func() { resolver.DirectHostResolver = old }()
	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	_, err = d.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "slow.example", DstPort: 443})
	assert.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), 3*time.Second)
}

// blockingResolver answers only when the lookup's context ends.
type blockingResolver struct{ *fixedResolver }

func (blockingResolver) LookupIP(ctx context.Context, _ string) ([]netip.Addr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (r blockingResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}

func (r blockingResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}

// Like DIRECT, the outbound refuses a connection that is its own coming
// back through a listener.
func TestDesyncRejectsLoop(t *testing.T) {
	d := newTestDesync(t, DesyncOption{TLSRec: "1+s"})
	if d.loopBack == nil {
		t.Skip("loopback detector disabled")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c
		}
	}()
	out, err := d.DialContext(context.Background(), desyncMetadata(ln.Addr()))
	require.NoError(t, err)
	defer out.Close()
	in := <-accepted
	defer in.Close()
	src := in.RemoteAddr().(*net.TCPAddr).AddrPort()
	inAddr := in.LocalAddr().(*net.TCPAddr).AddrPort()
	_, err = d.DialContext(context.Background(), &C.Metadata{
		NetWork: C.TCP, SrcIP: src.Addr().Unmap(), SrcPort: src.Port(),
		InIP: inAddr.Addr().Unmap(), InPort: inAddr.Port(), Host: "example.com", DstPort: 443,
	})
	assert.ErrorIs(t, err, loopback.ErrReject)
}

func TestDesyncOptionValidation(t *testing.T) {
	for name, option := range map[string]DesyncOption{
		"nothing":          {},
		"bad position":     {TLSRec: "x"},
		"bad split":        {Split: "1+q"},
		"empty position":   {TLSRec: "1+s,"},
		"negative delay":   {Split: "2", SplitDelay: -1},
		"long delay":       {Split: "2", SplitDelay: 1001},
		"delay alone":      {TLSRec: "1+s", SplitDelay: 10},
		"tfo":              {BasicOption: BasicOption{TFO: true}, TLSRec: "1+s"},
		"mptcp":            {BasicOption: BasicOption{MPTCP: true}, TLSRec: "1+s"},
		"dialer-proxy":     {BasicOption: BasicOption{DialerProxy: "vpn"}, TLSRec: "1+s"},
		"fake ttl":         {Fake: &DesyncFakeOption{TTL: 0}},
		"fake ttl 256":     {Fake: &DesyncFakeOption{TTL: 256}},
		"fake timeout":     {Fake: &DesyncFakeOption{TTL: 4, Timeout: 60001}},
		"udp ttl":          {UDP: &DesyncUDPOption{TTL: 0}},
		"udp repeats":      {UDP: &DesyncUDPOption{TTL: 4, Repeats: 17}},
		"udp packets":      {UDP: &DesyncUDPOption{TTL: 4, Packets: 9}},
		"udp negative ttl": {UDP: &DesyncUDPOption{TTL: -1}},
	} {
		option.Name = name
		_, err := NewDesync(option)
		assert.Error(t, err, name)
		if err != nil {
			assert.Contains(t, err.Error(), `desync "`+name+`"`, "the error names the outbound")
		}
	}

	for name, option := range map[string]DesyncOption{
		"tlsrec":     {TLSRec: "1+s"},
		"many":       {TLSRec: "1+s, 3, -2+s"},
		"split":      {Split: "2", SplitDelay: 5},
		"both":       {TLSRec: "1+s", Split: "1"},
		"ip-version": {BasicOption: BasicOption{IPVersion: C.IPv4Only, RoutingMark: 7}, TLSRec: "1+s"},
	} {
		option.Name = name
		d, err := NewDesync(option)
		require.NoError(t, err, name)
		assert.Equal(t, C.Desync, d.Type())
		assert.True(t, d.SupportUDP())
	}
}

// Where the library does not implement fake or udp, they are configuration
// errors that name the OS and say why.
func TestDesyncPlatformMethods(t *testing.T) {
	_, err := NewDesync(DesyncOption{Name: "fake", TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4, Prefix: -1, Timeout: 3000}})
	if desync.SupportsFake() {
		assert.NoError(t, err)
	} else {
		assert.ErrorIs(t, err, desync.ErrFakeUnsupported)
		assert.ErrorContains(t, err, "fake is not supported on "+runtime.GOOS)
	}
	_, err = NewDesync(DesyncOption{Name: "udp", UDP: &DesyncUDPOption{TTL: 4}})
	if desync.SupportsUDPFake() {
		assert.NoError(t, err)
	} else {
		assert.ErrorIs(t, err, desync.ErrUDPFakeUnsupported)
		assert.ErrorContains(t, err, "udp is not supported on "+runtime.GOOS)
	}
}

func TestDesyncMarshalJSON(t *testing.T) {
	d := newTestDesync(t, DesyncOption{TLSRec: "1+s,3", Split: "2", SplitDelay: 5})
	raw, err := d.MarshalJSON()
	require.NoError(t, err)
	var v struct {
		Type   string `json:"type"`
		ID     string `json:"id"`
		Desync struct {
			Strategy string `json:"strategy"`
			TCP      struct {
				TLSRec     []string `json:"tlsrec"`
				Split      []string `json:"split"`
				SplitDelay int      `json:"split-delay"`
				Fake       any      `json:"fake"`
			} `json:"tcp"`
			UDP any `json:"udp"`
		} `json:"desync"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	assert.Equal(t, "Desync", v.Type)
	assert.NotEmpty(t, v.ID)
	assert.Equal(t, "static", v.Desync.Strategy)
	assert.Equal(t, []string{"1+s", "3"}, v.Desync.TCP.TLSRec)
	assert.Equal(t, []string{"2"}, v.Desync.TCP.Split)
	assert.Equal(t, 5, v.Desync.TCP.SplitDelay)
	assert.Nil(t, v.Desync.TCP.Fake)
	assert.Nil(t, v.Desync.UDP)
}

// Without udp options, UDP is the plain DIRECT path.
func TestDesyncPlainUDP(t *testing.T) {
	d := newTestDesync(t, DesyncOption{TLSRec: "1+s"})
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()
	ap := server.LocalAddr().(*net.UDPAddr).AddrPort()
	pc, err := d.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP, DstIP: ap.Addr(), DstPort: ap.Port()})
	require.NoError(t, err)
	defer pc.Close()
	assert.Equal(t, []string{"desync-test"}, []string(pc.Chains()))
	_, err = pc.WriteTo([]byte("datagram"), server.LocalAddr())
	require.NoError(t, err)
	buf := make([]byte, 64)
	require.NoError(t, server.SetReadDeadline(time.Now().Add(3*time.Second)))
	n, _, err := server.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "datagram", string(buf[:n]))
}
