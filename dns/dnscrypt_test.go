package dns

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/poly1305" //nolint:staticcheck
	"golang.org/x/crypto/salsa20"
)

func buildDNSCryptStamp(props uint64, addr string, pk []byte, name string) string {
	b := []byte{stampProtoDNSCrypt}
	b = binary.LittleEndian.AppendUint64(b, props)
	for _, f := range [][]byte{[]byte(addr), pk, []byte(name)} {
		b = append(b, byte(len(f)))
		b = append(b, f...)
	}
	return "sdns://" + base64.RawURLEncoding.EncodeToString(b)
}

func TestDNSCryptStampParse(t *testing.T) {
	// Public resolver stamps (AdGuard, Quad9).
	s, err := parseDNSCryptStamp("sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20")
	require.NoError(t, err)
	assert.Equal(t, "176.103.130.130:5443", s.ServerAddr)
	assert.Equal(t, "2.dnscrypt.default.ns1.adguard.com.", s.ProviderName)
	assert.Equal(t, uint64(2), s.Props)
	assert.Len(t, s.ProviderPK, 32)

	s, err = parseDNSCryptStamp("sdns://AQMAAAAAAAAAEzE0OS4xMTIuMTEyLjEwOjg0NDMgZ8hHuMh1jNEgJFVDvnVnRt803x2EwAuMRwNo34Idhj4ZMi5kbnNjcnlwdC1jZXJ0LnF1YWQ5Lm5ldA")
	require.NoError(t, err)
	assert.Equal(t, "149.112.112.10:8443", s.ServerAddr)
	assert.Equal(t, "2.dnscrypt-cert.quad9.net.", s.ProviderName)

	pk := make([]byte, 32)
	for addr, want := range map[string]string{
		"192.0.2.1":          "192.0.2.1:443",
		"[2001:db8::1]":      "[2001:db8::1]:443",
		"2001:db8::1":        "[2001:db8::1]:443",
		"[2001:db8::1]:8443": "[2001:db8::1]:8443",
		"dns.example:5353":   "dns.example:5353",
	} {
		s, err := parseDNSCryptStamp(buildDNSCryptStamp(0, addr, pk, "2.dnscrypt-cert.example"))
		require.NoError(t, err, addr)
		assert.Equal(t, want, s.ServerAddr, addr)
	}

	for stamp, want := range map[string]string{
		"sdns://AgUAAAAAAAAAAAAOZG5zLmdvb2dsZS5jb20NL2V4cGVyaW1lbnRhbA":            "https://", // DoH
		"sdns://" + base64.RawURLEncoding.EncodeToString([]byte{stampProtoDoT, 0}): "tls://",
		"sdns://" + base64.RawURLEncoding.EncodeToString([]byte{stampProtoDoQ, 0}): "quic://",
		"sdns://not*base64":            "encoding",
		"sdns://":                      "empty",
		"https://dns.google/dns-query": "sdns://",
		buildDNSCryptStamp(0, "192.0.2.1", pk[:31], "2.dnscrypt-cert.x"):                                                                "32 bytes",
		buildDNSCryptStamp(0, "192.0.2.1", pk, ""):                                                                                      "empty",
		buildDNSCryptStamp(0, "192.0.2.1", pk, "x") + "AA":                                                                              "trailing",
		"sdns://" + base64.RawURLEncoding.EncodeToString(append([]byte{stampProtoDNSCrypt, 0, 0, 0, 0, 0, 0, 0, 0, 9}, "192.0.2.1"...)): "provider key",
	} {
		_, err := parseDNSCryptStamp(stamp)
		if assert.Error(t, err, stamp) {
			assert.Contains(t, err.Error(), want, stamp)
		}
	}
}

func signDNSCryptCert(t *testing.T, providerSK ed25519.PrivateKey, es uint16, resolverPK, magic []byte, serial uint32, from, to time.Time) []byte {
	b := make([]byte, dnsCryptCertSize)
	copy(b, dnsCryptCertMagic)
	binary.BigEndian.PutUint16(b[4:], es)
	copy(b[72:], resolverPK)
	copy(b[104:], magic)
	binary.BigEndian.PutUint32(b[112:], serial)
	binary.BigEndian.PutUint32(b[116:], uint32(from.Unix()))
	binary.BigEndian.PutUint32(b[120:], uint32(to.Unix()))
	copy(b[8:72], ed25519.Sign(providerSK, b[72:]))
	return b
}

func TestDNSCryptCertVerifyAndSelect(t *testing.T) {
	providerPK, providerSK, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, otherSK, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0)
	pk := bytes.Repeat([]byte{9}, 32)
	magic := []byte("12345678")

	good := signDNSCryptCert(t, providerSK, 2, pk, magic, 7, now.Add(-time.Hour), now.Add(time.Hour))
	c, err := parseDNSCryptCert(good, providerPK)
	require.NoError(t, err)
	assert.Equal(t, uint16(2), c.esVersion)
	assert.Equal(t, uint32(7), c.serial)
	assert.Equal(t, magic, c.clientMagic[:])
	assert.True(t, c.validAt(now))
	assert.False(t, c.validAt(now.Add(time.Hour)))

	tampered := append([]byte(nil), good...)
	tampered[110] ^= 1
	_, err = parseDNSCryptCert(tampered, providerPK)
	assert.ErrorContains(t, err, "signature")
	_, err = parseDNSCryptCert(signDNSCryptCert(t, otherSK, 2, pk, magic, 7, now, now.Add(time.Hour)), providerPK)
	assert.ErrorContains(t, err, "signature")
	_, err = parseDNSCryptCert(signDNSCryptCert(t, providerSK, 3, pk, magic, 7, now, now.Add(time.Hour)), providerPK)
	assert.ErrorContains(t, err, "es-version")
	_, err = parseDNSCryptCert(good[:100], providerPK)
	assert.ErrorContains(t, err, "short")

	certs := [][]byte{
		signDNSCryptCert(t, providerSK, 1, pk, magic, 8, now.Add(-time.Hour), now.Add(time.Hour)),
		good,
		signDNSCryptCert(t, providerSK, 2, pk, magic, 8, now.Add(-time.Hour), now.Add(time.Hour)),
		signDNSCryptCert(t, providerSK, 2, pk, magic, 99, now.Add(-2*time.Hour), now.Add(-time.Hour)), // expired
		signDNSCryptCert(t, otherSK, 2, pk, magic, 100, now.Add(-time.Hour), now.Add(time.Hour)),      // forged
	}
	best, err := selectDNSCryptCert(certs, providerPK, now)
	require.NoError(t, err)
	assert.Equal(t, uint32(8), best.serial)
	assert.Equal(t, uint16(2), best.esVersion)

	_, err = selectDNSCryptCert(certs[3:], providerPK, now)
	assert.Error(t, err)
}

// The XChaCha20 secretbox follows the same layout as the XSalsa20 one: the
// same code with the XSalsa20 keystream must match nacl/secretbox exactly.
func TestDNSCryptSecretboxLayout(t *testing.T) {
	var key [32]byte
	var nonce [24]byte
	rand.Read(key[:])
	rand.Read(nonce[:])
	msg := make([]byte, 200)
	rand.Read(msg)

	stream := make([]byte, 32+len(msg))
	copy(stream[32:], msg)
	salsa20.XORKeyStream(stream, stream, nonce[:], &key)
	var polyKey [32]byte
	copy(polyKey[:], stream[:32])
	var tag [16]byte
	poly1305.Sum(&tag, stream[32:], &polyKey)
	assert.Equal(t, secretbox.Seal(nil, msg, &nonce, &key), append(tag[:], stream[32:]...))
}

func TestDNSCryptCryptoRoundTrip(t *testing.T) {
	for _, es := range []uint16{dnsCryptESXSalsa20, dnsCryptESXChacha20} {
		var clientSK, serverSK, clientPK, serverPK [32]byte
		rand.Read(clientSK[:])
		rand.Read(serverSK[:])
		p, _ := curve25519.X25519(clientSK[:], curve25519.Basepoint)
		copy(clientPK[:], p)
		p, _ = curve25519.X25519(serverSK[:], curve25519.Basepoint)
		copy(serverPK[:], p)

		k1, err := dnsCryptSharedKey(es, &clientSK, &serverPK)
		require.NoError(t, err)
		k2, err := dnsCryptSharedKey(es, &serverSK, &clientPK)
		require.NoError(t, err)
		require.Equal(t, k1, k2)

		var nonce [24]byte
		rand.Read(nonce[:])
		for _, n := range []int{0, 1, 31, 32, 33, 64, 500} {
			msg := make([]byte, n)
			rand.Read(msg)
			box := dnsCryptSeal(es, &k1, &nonce, msg)
			require.Len(t, box, n+16)
			out, ok := dnsCryptOpen(es, &k2, &nonce, box)
			require.True(t, ok, "es %d len %d", es, n)
			require.True(t, bytes.Equal(msg, out))
			box[len(box)-1] ^= 1
			_, ok = dnsCryptOpen(es, &k2, &nonce, box)
			require.False(t, ok)
		}
	}
	_, err := dnsCryptSharedKey(2, &[32]byte{1}, &[32]byte{}) // low-order point
	assert.Error(t, err)

	for _, n := range []int{0, 10, 63, 64, 300} {
		msg := bytes.Repeat([]byte{0x80}, n)
		p := dnsCryptPad(msg, 256)
		assert.Zero(t, len(p)%64)
		assert.GreaterOrEqual(t, len(p), 256)
		u, err := dnsCryptUnpad(p)
		require.NoError(t, err)
		assert.Equal(t, msg, u)
	}
	_, err = dnsCryptUnpad(make([]byte, 64))
	assert.Error(t, err)
}

// fakeDNSCryptServer is an in-process DNSCrypt resolver listening on the same
// UDP and TCP port.
type fakeDNSCryptServer struct {
	providerPK   ed25519.PublicKey
	providerSK   ed25519.PrivateKey
	providerName string
	addr         string
	udp          net.PacketConn
	tcp          net.Listener

	mu        sync.Mutex
	published [][]byte
	keys      map[[8]byte]*fakeServerKey

	certQueries atomic.Int32
	udpQueries  atomic.Int32
	tcpQueries  atomic.Int32
	truncated   atomic.Int32
}

type fakeServerKey struct {
	es uint16
	sk [32]byte
}

func newFakeDNSCryptServer(t *testing.T) *fakeDNSCryptServer {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	s := &fakeDNSCryptServer{
		providerPK: pk, providerSK: sk,
		providerName: "2.dnscrypt-cert.test.",
		keys:         map[[8]byte]*fakeServerKey{},
	}
	for i := 0; ; i++ {
		// Pick UDP first: Windows may assign a free TCP port from a range
		// reserved for UDP, causing every nearby retry to fail with WSAEACCES.
		s.udp, err = net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		s.addr = s.udp.LocalAddr().String()
		if s.tcp, err = net.Listen("tcp", s.addr); err == nil {
			break
		}
		s.udp.Close()
		require.Less(t, i, 100, "no free port pair: %v", err)
	}
	t.Cleanup(func() { s.udp.Close(); s.tcp.Close() })
	go s.serveUDP()
	go s.serveTCP()
	return s
}

func (s *fakeDNSCryptServer) stamp() string {
	return buildDNSCryptStamp(0, s.addr, s.providerPK, s.providerName)
}

// newCert creates a resolver key and its signed certificate; the key is
// accepted from now on.
func (s *fakeDNSCryptServer) newCert(t *testing.T, es uint16, serial uint32, from, to time.Time) (raw []byte, magic [8]byte) {
	k := &fakeServerKey{es: es}
	rand.Read(k.sk[:])
	rand.Read(magic[:])
	pk, err := curve25519.X25519(k.sk[:], curve25519.Basepoint)
	require.NoError(t, err)
	s.mu.Lock()
	s.keys[magic] = k
	s.mu.Unlock()
	return signDNSCryptCert(t, s.providerSK, es, pk, magic[:], serial, from, to), magic
}

func (s *fakeDNSCryptServer) publish(certs ...[]byte) {
	s.mu.Lock()
	s.published = certs
	s.mu.Unlock()
}

func (s *fakeDNSCryptServer) revoke(magic [8]byte) {
	s.mu.Lock()
	delete(s.keys, magic)
	s.mu.Unlock()
}

func (s *fakeDNSCryptServer) serveUDP() {
	buf := make([]byte, 65535)
	for {
		n, from, err := s.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		if resp := s.handle(append([]byte(nil), buf[:n]...), false); resp != nil {
			s.udp.WriteTo(resp, from)
		}
	}
}

func (s *fakeDNSCryptServer) serveTCP() {
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			var l [2]byte
			if _, err := io.ReadFull(conn, l[:]); err != nil {
				return
			}
			q := make([]byte, binary.BigEndian.Uint16(l[:]))
			if _, err := io.ReadFull(conn, q); err != nil {
				return
			}
			if resp := s.handle(q, true); resp != nil {
				conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...))
			}
		}()
	}
}

func txtEscape(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x21 && c <= 0x7e && c != '\\' && c != '"' && c != ';' {
			sb.WriteByte(c)
		} else {
			sb.WriteString("\\")
			sb.WriteString(string([]byte{'0' + c/100, '0' + c/10%10, '0' + c%10}))
		}
	}
	return sb.String()
}

func (s *fakeDNSCryptServer) handle(p []byte, tcp bool) []byte {
	var magic [8]byte
	copy(magic[:], p)
	s.mu.Lock()
	key := s.keys[magic]
	s.mu.Unlock()

	if key == nil || len(p) < 52+16 { // plaintext certificate query
		q := new(D.Msg)
		if q.Unpack(p) != nil || len(q.Question) != 1 || q.Question[0].Qtype != D.TypeTXT || q.Question[0].Name != s.providerName {
			return nil
		}
		s.certQueries.Add(1)
		r := new(D.Msg)
		r.SetReply(q)
		s.mu.Lock()
		for _, c := range s.published {
			r.Answer = append(r.Answer, &D.TXT{
				Hdr: D.RR_Header{Name: s.providerName, Rrtype: D.TypeTXT, Class: D.ClassINET, Ttl: 60},
				Txt: []string{txtEscape(c)},
			})
		}
		s.mu.Unlock()
		out, _ := r.Pack()
		return out
	}

	if tcp {
		s.tcpQueries.Add(1)
	} else {
		s.udpQueries.Add(1)
	}
	var clientPK [32]byte
	copy(clientPK[:], p[8:40])
	var nonce [24]byte
	copy(nonce[:12], p[40:52])
	shared, err := dnsCryptSharedKey(key.es, &key.sk, &clientPK)
	if err != nil {
		return nil
	}
	plain, ok := dnsCryptOpen(key.es, &shared, &nonce, p[52:])
	if !ok {
		return nil
	}
	plain, err = dnsCryptUnpad(plain)
	if err != nil {
		return nil
	}
	q := new(D.Msg)
	if q.Unpack(plain) != nil || len(q.Question) != 1 {
		return nil
	}
	r := new(D.Msg)
	r.SetReply(q)
	name := q.Question[0].Name
	if strings.HasPrefix(name, "big.") {
		for i := 0; i < 20; i++ {
			r.Answer = append(r.Answer, &D.TXT{
				Hdr: D.RR_Header{Name: name, Rrtype: D.TypeTXT, Class: D.ClassINET, Ttl: 60},
				Txt: []string{strings.Repeat("x", 200)},
			})
		}
	} else {
		r.Answer = append(r.Answer, &D.A{
			Hdr: D.RR_Header{Name: name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 1),
		})
	}
	out, _ := r.Pack()
	if !tcp && len(out) > len(p) { // the response may not be larger than the query
		r.Answer = nil
		r.Truncated = true
		out, _ = r.Pack()
		s.truncated.Add(1)
	}
	rand.Read(nonce[12:])
	sealed := dnsCryptSeal(key.es, &shared, &nonce, dnsCryptPad(out, 0))
	return append(append(append([]byte(nil), dnsCryptResolverMagic...), nonce[:]...), sealed...)
}

type countingDialer struct {
	net.Dialer
	mu    sync.Mutex
	calls map[string]int
}

func (d *countingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	if d.calls == nil {
		d.calls = map[string]int{}
	}
	d.calls[network]++
	d.mu.Unlock()
	return d.Dialer.DialContext(ctx, network, addr)
}

func (d *countingDialer) count(network string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls[network]
}

type fakeClock struct{ ns atomic.Int64 }

func (c *fakeClock) now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *fakeClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

func newTestDNSCryptClient(t *testing.T, s *fakeDNSCryptServer) (*dnsCryptClient, *countingDialer, *fakeClock) {
	c, err := newDNSCryptClient(s.stamp(), nil, nil, "")
	require.NoError(t, err)
	d := &countingDialer{}
	clock := &fakeClock{}
	clock.ns.Store(time.Now().UnixNano())
	c.dialer = d
	c.now = clock.now
	return c, d, clock
}

func dnsCryptQuery(t *testing.T, c *dnsCryptClient, name string, qtype uint16) *D.Msg {
	t.Helper()
	m := new(D.Msg)
	m.SetQuestion(name, qtype)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := c.ExchangeContext(ctx, m)
	require.NoError(t, err)
	require.Equal(t, m.Id, r.Id)
	return r
}

func TestDNSCryptExchange(t *testing.T) {
	for _, es := range []uint16{dnsCryptESXSalsa20, dnsCryptESXChacha20} {
		s := newFakeDNSCryptServer(t)
		now := time.Now()
		cert, _ := s.newCert(t, es, 1, now.Add(-time.Hour), now.Add(time.Hour))
		s.publish(cert)
		c, d, _ := newTestDNSCryptClient(t, s)

		// Concurrent first queries share a single certificate fetch.
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				m := new(D.Msg)
				m.SetQuestion("example.com.", D.TypeA)
				r, err := c.ExchangeContext(context.Background(), m)
				if assert.NoError(t, err) && assert.Len(t, r.Answer, 1) {
					assert.Equal(t, "192.0.2.1", r.Answer[0].(*D.A).A.String())
				}
			}()
		}
		wg.Wait()
		assert.Equal(t, int32(1), s.certQueries.Load(), "es %d", es)
		assert.Equal(t, int32(8), s.udpQueries.Load())
		assert.Zero(t, s.tcpQueries.Load())

		// A large answer is truncated over UDP and retried over TCP.
		r := dnsCryptQuery(t, c, "big.example.com.", D.TypeTXT)
		assert.False(t, r.Truncated)
		assert.Len(t, r.Answer, 20)
		assert.Equal(t, int32(1), s.truncated.Load())
		assert.Equal(t, int32(1), s.tcpQueries.Load())

		// Every connection went through the injected dialer.
		assert.Equal(t, 1+8+1, d.count("udp"))
		assert.Equal(t, 1, d.count("tcp"))
	}
}

func TestDNSCryptCertRotation(t *testing.T) {
	s := newFakeDNSCryptServer(t)
	now := time.Now()
	cert1, magic1 := s.newCert(t, dnsCryptESXChacha20, 1, now.Add(-time.Hour), now.Add(time.Hour))
	s.publish(cert1)
	c, _, clock := newTestDNSCryptClient(t, s)

	dnsCryptQuery(t, c, "a.example.", D.TypeA)
	require.Equal(t, uint32(1), c.session.Load().cert.serial)

	// A new certificate appears; the old one still works until the client
	// refreshes in the background.
	cert2, _ := s.newCert(t, dnsCryptESXSalsa20, 2, now.Add(-time.Minute), now.Add(3*time.Hour))
	s.publish(cert1, cert2)
	dnsCryptQuery(t, c, "a.example.", D.TypeA)
	assert.Equal(t, int32(1), s.certQueries.Load(), "no refresh before refreshAt")

	clock.advance(31 * time.Minute) // past refreshAt (half of the remaining hour)
	dnsCryptQuery(t, c, "a.example.", D.TypeA)
	require.Eventually(t, func() bool { return c.session.Load().cert.serial == 2 }, 3*time.Second, 10*time.Millisecond)

	s.revoke(magic1)
	dnsCryptQuery(t, c, "a.example.", D.TypeA)

	// Expired certificate: the query waits for a new one.
	cert3, _ := s.newCert(t, dnsCryptESXChacha20, 3, now.Add(time.Hour), now.Add(48*time.Hour))
	s.publish(cert3)
	clock.advance(3 * time.Hour)
	dnsCryptQuery(t, c, "a.example.", D.TypeA)
	assert.Equal(t, uint32(3), c.session.Load().cert.serial)

	// A failed background refresh keeps the current session and backs off.
	s.publish()
	before := s.certQueries.Load()
	clock.advance(2 * time.Hour)
	dnsCryptQuery(t, c, "a.example.", D.TypeA)
	require.Eventually(t, func() bool { return s.certQueries.Load() == before+1 }, 3*time.Second, 10*time.Millisecond)
	dnsCryptQuery(t, c, "a.example.", D.TypeA)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, before+1, s.certQueries.Load())
	assert.Equal(t, uint32(3), c.session.Load().cert.serial)
}

func TestDNSCryptNoValidCert(t *testing.T) {
	s := newFakeDNSCryptServer(t)
	_, otherSK, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	forged := signDNSCryptCert(t, otherSK, 2, make([]byte, 32), []byte("abcdefgh"), 1, now.Add(-time.Hour), now.Add(time.Hour))
	s.publish(forged)
	c, _, _ := newTestDNSCryptClient(t, s)
	m := new(D.Msg)
	m.SetQuestion("example.com.", D.TypeA)
	_, err := c.ExchangeContext(context.Background(), m)
	assert.ErrorContains(t, err, "signature")
}

func TestDNSCryptTransform(t *testing.T) {
	s := newFakeDNSCryptServer(t)
	clients := transform([]NameServer{{Net: "dnscrypt", Addr: s.stamp()}, {Net: "dnscrypt", Addr: "sdns://AgUAAAAAAAAAAAAOZG5zLmdvb2dsZS5jb20NL2V4cGVyaW1lbnRhbA"}}, nil)
	require.Len(t, clients, 2)
	assert.IsType(t, &dnsCryptClient{}, clients[0])
	assert.Contains(t, clients[0].Address(), s.addr)
	_, err := clients[1].ExchangeContext(context.Background(), new(D.Msg))
	assert.ErrorContains(t, err, "https://")
}
