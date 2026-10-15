package dns

// A DNSCrypt v2 client (https://dnscrypt.info/protocol) for sdns:// stamps.
//
// Everything is implemented on top of golang.org/x/crypto so it builds on all
// targets, and every connection (the certificate query as well as the
// encrypted queries) goes through the same DNS dialer as the udp:// and tcp://
// clients, so #proxy, respect-rules, interface binding and routing mark apply.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/poly1305" //nolint:staticcheck // the XChaCha20 secretbox construction needs raw Poly1305
	"golang.org/x/crypto/salsa20/salsa"
	"golang.org/x/sync/singleflight"
)

const (
	dnsCryptCertSize      = 124
	dnsCryptESXSalsa20    = 1 // X25519-XSalsa20Poly1305
	dnsCryptESXChacha20   = 2 // X25519-XChacha20Poly1305
	dnsCryptMinUDPQuery   = 256
	dnsCryptPadBlock      = 64
	dnsCryptMaxPacket     = 65535
	dnsCryptHalfNonce     = 12
	dnsCryptNonceSize     = 24
	dnsCryptTagSize       = 16
	dnsCryptRefreshMax    = time.Hour
	dnsCryptRetryInterval = 30 * time.Second
)

var (
	dnsCryptCertMagic     = []byte("DNSC")
	dnsCryptResolverMagic = []byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}
)

type contextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// dnsCryptCert is a verified resolver certificate.
type dnsCryptCert struct {
	esVersion   uint16
	resolverPK  [32]byte
	clientMagic [8]byte
	serial      uint32
	notBefore   time.Time
	notAfter    time.Time
}

func (c *dnsCryptCert) validAt(t time.Time) bool {
	return !t.Before(c.notBefore) && t.Before(c.notAfter)
}

// parseDNSCryptCert parses a binary certificate and verifies its signature
// with the provider key from the stamp.
func parseDNSCryptCert(b []byte, providerPK ed25519.PublicKey) (*dnsCryptCert, error) {
	if len(b) < dnsCryptCertSize {
		return nil, fmt.Errorf("certificate too short (%d bytes)", len(b))
	}
	if !bytes.Equal(b[:4], dnsCryptCertMagic) {
		return nil, errors.New("bad certificate magic")
	}
	es := binary.BigEndian.Uint16(b[4:6])
	if es != dnsCryptESXSalsa20 && es != dnsCryptESXChacha20 {
		return nil, fmt.Errorf("unsupported es-version %d", es)
	}
	if !ed25519.Verify(providerPK, b[72:], b[8:72]) {
		return nil, errors.New("certificate signature verification failed")
	}
	c := &dnsCryptCert{
		esVersion: es,
		serial:    binary.BigEndian.Uint32(b[112:116]),
		notBefore: time.Unix(int64(binary.BigEndian.Uint32(b[116:120])), 0),
		notAfter:  time.Unix(int64(binary.BigEndian.Uint32(b[120:124])), 0),
	}
	copy(c.resolverPK[:], b[72:104])
	copy(c.clientMagic[:], b[104:112])
	if bytes.Equal(c.clientMagic[:], dnsCryptResolverMagic) {
		return nil, errors.New("certificate client magic collides with the resolver magic")
	}
	return c, nil
}

// selectDNSCryptCert picks the valid certificate with the highest serial,
// preferring XChaCha20 on a tie.
func selectDNSCryptCert(raws [][]byte, providerPK ed25519.PublicKey, now time.Time) (*dnsCryptCert, error) {
	var best *dnsCryptCert
	var lastErr error
	for _, raw := range raws {
		c, err := parseDNSCryptCert(raw, providerPK)
		if err != nil {
			lastErr = err
			continue
		}
		if !c.validAt(now) {
			lastErr = fmt.Errorf("certificate serial %d is not valid now (%s - %s)", c.serial, c.notBefore.UTC(), c.notAfter.UTC())
			continue
		}
		if best == nil || c.serial > best.serial || (c.serial == best.serial && c.esVersion > best.esVersion) {
			best = c
		}
	}
	if best == nil {
		if lastErr == nil {
			lastErr = errors.New("no certificate in the response")
		}
		return nil, lastErr
	}
	return best, nil
}

// dnsCryptSharedKey derives the precomputed box key for the es-version.
func dnsCryptSharedKey(es uint16, secret, public *[32]byte) (key [32]byte, err error) {
	dh, err := curve25519.X25519(secret[:], public[:])
	if err != nil {
		return key, err
	}
	var zero [16]byte
	switch es {
	case dnsCryptESXSalsa20: // crypto_box_beforenm
		var in [32]byte
		copy(in[:], dh)
		salsa.HSalsa20(&key, &zero, &in, &salsa.Sigma)
	case dnsCryptESXChacha20: // crypto_box_curve25519xchacha20poly1305_beforenm
		sub, err := chacha20.HChaCha20(dh, zero[:])
		if err != nil {
			return key, err
		}
		copy(key[:], sub)
	default:
		return key, fmt.Errorf("unsupported es-version %d", es)
	}
	return key, nil
}

// dnsCryptSeal returns tag||ciphertext (the NaCl secretbox layout used by
// both DNSCrypt constructions).
func dnsCryptSeal(es uint16, key *[32]byte, nonce *[24]byte, msg []byte) []byte {
	if es == dnsCryptESXSalsa20 {
		return secretbox.Seal(nil, msg, nonce, key)
	}
	// crypto_secretbox_xchacha20poly1305: the first 32 keystream bytes are
	// the Poly1305 key, the message is encrypted with the keystream after them.
	c, _ := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	var polyKey [32]byte
	c.XORKeyStream(polyKey[:], polyKey[:])
	out := make([]byte, dnsCryptTagSize+len(msg))
	c.XORKeyStream(out[dnsCryptTagSize:], msg)
	var tag [dnsCryptTagSize]byte
	poly1305.Sum(&tag, out[dnsCryptTagSize:], &polyKey)
	copy(out, tag[:])
	return out
}

func dnsCryptOpen(es uint16, key *[32]byte, nonce *[24]byte, box []byte) ([]byte, bool) {
	if es == dnsCryptESXSalsa20 {
		return secretbox.Open(nil, box, nonce, key)
	}
	if len(box) < dnsCryptTagSize {
		return nil, false
	}
	c, _ := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	var polyKey [32]byte
	c.XORKeyStream(polyKey[:], polyKey[:])
	var tag [dnsCryptTagSize]byte
	copy(tag[:], box)
	if !poly1305.Verify(&tag, box[dnsCryptTagSize:], &polyKey) {
		return nil, false
	}
	out := make([]byte, len(box)-dnsCryptTagSize)
	c.XORKeyStream(out, box[dnsCryptTagSize:])
	return out, true
}

// dnsCryptPad applies ISO/IEC 7816-4 padding up to a multiple of 64 bytes and
// at least minLen bytes.
func dnsCryptPad(msg []byte, minLen int) []byte {
	n := len(msg) + 1
	if n < minLen {
		n = minLen
	}
	n = (n + dnsCryptPadBlock - 1) / dnsCryptPadBlock * dnsCryptPadBlock
	out := make([]byte, n)
	copy(out, msg)
	out[len(msg)] = 0x80
	return out
}

func dnsCryptUnpad(b []byte) ([]byte, error) {
	i := len(b) - 1
	for i >= 0 && b[i] == 0 {
		i--
	}
	if i < 0 || b[i] != 0x80 {
		return nil, errors.New("invalid padding")
	}
	return b[:i], nil
}

// dnsCryptSession is the state derived from one certificate. It is immutable.
type dnsCryptSession struct {
	cert      *dnsCryptCert
	clientPK  [32]byte
	sharedKey [32]byte
	refreshAt time.Time
}

func newDNSCryptSession(cert *dnsCryptCert, now time.Time) (*dnsCryptSession, error) {
	var sk [32]byte
	if _, err := io.ReadFull(rand.Reader, sk[:]); err != nil {
		return nil, err
	}
	pk, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	s := &dnsCryptSession{cert: cert}
	copy(s.clientPK[:], pk)
	if s.sharedKey, err = dnsCryptSharedKey(cert.esVersion, &sk, &cert.resolverPK); err != nil {
		return nil, err
	}
	// Refresh well before expiry so a rotated certificate is picked up in the
	// background, while the current one keeps serving queries.
	refresh := cert.notAfter.Sub(now) / 2
	if refresh > dnsCryptRefreshMax {
		refresh = dnsCryptRefreshMax
	}
	s.refreshAt = now.Add(refresh)
	return s, nil
}

// encrypt builds an encrypted query; the returned nonce is needed to decrypt
// the response.
func (s *dnsCryptSession) encrypt(packed []byte, minLen int) ([]byte, [dnsCryptNonceSize]byte, error) {
	var nonce [dnsCryptNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:dnsCryptHalfNonce]); err != nil {
		return nil, nonce, err
	}
	sealed := dnsCryptSeal(s.cert.esVersion, &s.sharedKey, &nonce, dnsCryptPad(packed, minLen))
	out := make([]byte, 0, 8+32+dnsCryptHalfNonce+len(sealed))
	out = append(out, s.cert.clientMagic[:]...)
	out = append(out, s.clientPK[:]...)
	out = append(out, nonce[:dnsCryptHalfNonce]...)
	out = append(out, sealed...)
	return out, nonce, nil
}

func (s *dnsCryptSession) decrypt(resp []byte, nonce [dnsCryptNonceSize]byte) ([]byte, error) {
	if len(resp) < len(dnsCryptResolverMagic)+dnsCryptNonceSize+dnsCryptTagSize {
		return nil, errors.New("DNSCrypt response too short")
	}
	if !bytes.Equal(resp[:8], dnsCryptResolverMagic) {
		return nil, errors.New("bad DNSCrypt response magic")
	}
	if !bytes.Equal(resp[8:8+dnsCryptHalfNonce], nonce[:dnsCryptHalfNonce]) {
		return nil, errors.New("DNSCrypt response nonce mismatch")
	}
	var full [dnsCryptNonceSize]byte
	copy(full[:], resp[8:8+dnsCryptNonceSize])
	plain, ok := dnsCryptOpen(s.cert.esVersion, &s.sharedKey, &full, resp[8+dnsCryptNonceSize:])
	if !ok {
		return nil, errors.New("DNSCrypt response decryption failed")
	}
	return dnsCryptUnpad(plain)
}

type dnsCryptClient struct {
	addr   string // the sdns:// stamp, without the #fragment
	stamp  *dnsCryptStamp
	dialer contextDialer
	now    func() time.Time

	session atomic.Pointer[dnsCryptSession]
	retryAt atomic.Int64 // unix nanos; no background refresh before it
	group   singleflight.Group
}

var _ dnsClient = (*dnsCryptClient)(nil)

func newDNSCryptClient(addr string, r resolver.Resolver, proxyAdapter C.ProxyAdapter, proxyName string) (*dnsCryptClient, error) {
	stamp, err := parseDNSCryptStamp(addr)
	if err != nil {
		return nil, err
	}
	return &dnsCryptClient{
		addr:   addr,
		stamp:  stamp,
		dialer: newDNSDialer(r, proxyAdapter, proxyName),
		now:    time.Now,
	}, nil
}

// Address implements dnsClient
func (c *dnsCryptClient) Address() string {
	return fmt.Sprintf("dnscrypt://%s (%s)", c.stamp.ServerAddr, c.stamp.ProviderName)
}

// ResetConnection drops the cached certificate; the next query fetches it again.
func (c *dnsCryptClient) ResetConnection() {
	c.session.Store(nil)
	c.retryAt.Store(0)
}

func (c *dnsCryptClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	sess, err := c.getSession(ctx)
	if err != nil {
		return nil, err
	}
	packed, err := m.Pack()
	if err != nil {
		return nil, err
	}
	msg, err := c.exchange(ctx, sess, "udp", packed)
	// The server sets TC when the response does not fit in the padded query.
	if err == nil && msg.Truncated {
		log.Debugln("[DNS] Truncated reply from %s for %s over UDP, retrying over TCP", c.Address(), msgToDomain(m))
		msg, err = c.exchange(ctx, sess, "tcp", packed)
	}
	if err != nil && ctx.Err() == nil {
		// The resolver may have rotated its keys: look for a new certificate.
		c.refreshAsync()
	}
	return msg, err
}

func (c *dnsCryptClient) exchange(ctx context.Context, sess *dnsCryptSession, network string, packed []byte) (*D.Msg, error) {
	minLen := 0
	if network == "udp" {
		minLen = dnsCryptMinUDPQuery
	}
	query, nonce, err := sess.encrypt(packed, minLen)
	if err != nil {
		return nil, err
	}
	resp, err := c.roundTrip(ctx, network, query)
	if err != nil {
		return nil, err
	}
	plain, err := sess.decrypt(resp, nonce)
	if err != nil {
		return nil, err
	}
	msg := new(D.Msg)
	if err := msg.Unpack(plain); err != nil {
		return nil, err
	}
	return msg, nil
}

// roundTrip sends one packet and reads one reply over a connection from the
// DNS dialer; TCP uses the two-byte length prefix.
func (c *dnsCryptClient) roundTrip(ctx context.Context, network string, payload []byte) ([]byte, error) {
	conn, err := c.dialer.DialContext(ctx, network, c.stamp.ServerAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(DefaultTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close() // unblock the read
		case <-done:
		}
	}()

	resp, err := func() ([]byte, error) {
		if network == "udp" {
			if _, err := conn.Write(payload); err != nil {
				return nil, err
			}
			buf := make([]byte, dnsCryptMaxPacket)
			n, err := conn.Read(buf)
			if err != nil {
				return nil, err
			}
			return buf[:n], nil
		}
		if len(payload) > dnsCryptMaxPacket {
			return nil, errors.New("DNSCrypt query too large")
		}
		buf := make([]byte, 2+len(payload))
		binary.BigEndian.PutUint16(buf, uint16(len(payload)))
		copy(buf[2:], payload)
		if _, err := conn.Write(buf); err != nil {
			return nil, err
		}
		var l [2]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return nil, err
		}
		out := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(conn, out); err != nil {
			return nil, err
		}
		return out, nil
	}()
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return resp, err
}

// getSession returns the current session. A missing or expired certificate is
// fetched once for all waiting queries (singleflight); a certificate that is
// due for refresh keeps serving while a new one is fetched in the background.
func (c *dnsCryptClient) getSession(ctx context.Context) (*dnsCryptSession, error) {
	now := c.now()
	if s := c.session.Load(); s != nil && s.cert.validAt(now) {
		if !now.Before(s.refreshAt) {
			c.refreshAsync()
		}
		return s, nil
	}
	ch := c.group.DoChan("cert", c.fetchSession)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.Err != nil {
			return nil, r.Err
		}
		return r.Val.(*dnsCryptSession), nil
	}
}

func (c *dnsCryptClient) refreshAsync() {
	if c.now().UnixNano() < c.retryAt.Load() {
		return
	}
	c.group.DoChan("cert", c.fetchSession) // buffered channel, the result is not needed
}

func (c *dnsCryptClient) fetchSession() (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()
	sess, err := c.fetchSessionContext(ctx)
	// Rate-limit background fetches (failed queries also trigger them); a
	// query without a usable certificate still fetches synchronously.
	c.retryAt.Store(c.now().Add(dnsCryptRetryInterval).UnixNano())
	if err != nil {
		log.Warnln("[DNS] DNSCrypt %s: %v", c.Address(), err)
		return nil, err
	}
	if old := c.session.Load(); old == nil || old.cert.serial != sess.cert.serial {
		log.Debugln("[DNS] DNSCrypt %s: using certificate serial %d (es-version %d), valid until %s",
			c.Address(), sess.cert.serial, sess.cert.esVersion, sess.cert.notAfter.UTC())
	}
	c.session.Store(sess)
	return sess, nil
}

func (c *dnsCryptClient) fetchSessionContext(ctx context.Context) (*dnsCryptSession, error) {
	q := new(D.Msg)
	q.SetQuestion(c.stamp.ProviderName, D.TypeTXT)
	q.RecursionDesired = true
	packed, err := q.Pack()
	if err != nil {
		return nil, err
	}
	resp, err := c.queryCert(ctx, "udp", q.Id, packed)
	if err == nil && resp.Truncated {
		resp, err = c.queryCert(ctx, "tcp", q.Id, packed)
	}
	if err != nil {
		return nil, fmt.Errorf("fetching certificate: %w", err)
	}
	var raws [][]byte
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*D.TXT); ok {
			if raw, err := txtRawData(txt); err == nil {
				raws = append(raws, raw)
			}
		}
	}
	now := c.now()
	cert, err := selectDNSCryptCert(raws, c.stamp.ProviderPK, now)
	if err != nil {
		return nil, fmt.Errorf("no usable certificate: %w", err)
	}
	return newDNSCryptSession(cert, now)
}

func (c *dnsCryptClient) queryCert(ctx context.Context, network string, id uint16, packed []byte) (*D.Msg, error) {
	raw, err := c.roundTrip(ctx, network, packed)
	if err != nil {
		return nil, err
	}
	msg := new(D.Msg)
	if err := msg.Unpack(raw); err != nil {
		return nil, err
	}
	if msg.Id != id {
		return nil, errors.New("certificate response id mismatch")
	}
	if msg.Rcode != D.RcodeSuccess {
		return nil, fmt.Errorf("certificate query: %s", D.RcodeToString[msg.Rcode])
	}
	return msg, nil
}

// txtRawData returns the concatenated, unescaped character-strings of a TXT
// record by packing it back to wire format.
func txtRawData(txt *D.TXT) ([]byte, error) {
	rr := *txt
	rr.Hdr.Name = "." // a 1-byte owner name, so the RDATA starts at a known offset
	buf := make([]byte, D.Len(&rr)+1)
	off, err := D.PackRR(&rr, buf, 0, nil, false)
	if err != nil {
		return nil, err
	}
	const rdataStart = 1 + 10 // root name + type, class, ttl, rdlength
	if off < rdataStart {
		return nil, errors.New("short TXT record")
	}
	rdata := buf[rdataStart:off]
	var out []byte
	for len(rdata) > 0 {
		n := int(rdata[0])
		if len(rdata) < 1+n {
			return nil, errors.New("malformed TXT record")
		}
		out = append(out, rdata[1:1+n]...)
		rdata = rdata[1+n:]
	}
	return out, nil
}

// errorClient stands in for a nameserver that could not be set up, so a bad
// entry fails its queries instead of the whole configuration.
type errorClient struct {
	addr string
	err  error
}

var _ dnsClient = errorClient{}

func (c errorClient) Address() string { return c.addr }

func (c errorClient) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) { return nil, c.err }

func (c errorClient) ResetConnection() {}
