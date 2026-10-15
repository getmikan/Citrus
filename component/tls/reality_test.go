package tls

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mldsa"
	utls "github.com/metacubex/utls"
)

const (
	mlkem768EncapsulationKeySize = 1184
	x25519MLKEM768KeyShareSize   = mlkem768EncapsulationKeySize + 32
)

// checkRealityKeyShares mirrors the client hello check of the Xray REALITY server since
// XTLS/REALITY@8cdf7bf: one X25519MLKEM768 key share, placed before an optional X25519 one.
func checkRealityKeyShares(keyShares []utls.KeyShare) bool {
	var peerPub, peerPub2 []byte
	for _, keyShare := range keyShares {
		if keyShare.Group == utls.X25519MLKEM768 && len(keyShare.Data) == x25519MLKEM768KeyShareSize {
			if peerPub2 != nil {
				return false
			}
			peerPub2 = keyShare.Data[mlkem768EncapsulationKeySize:]
			continue
		}
		if keyShare.Group == utls.X25519 && len(keyShare.Data) == 32 {
			if peerPub != nil {
				return false
			}
			peerPub = keyShare.Data
			break
		}
	}
	return peerPub2 != nil
}

func buildTestRealityHello(t *testing.T, fingerprint UClientHelloID, realityConfig *RealityConfig) *utls.UConn {
	t.Helper()
	conn, peer := net.Pipe()
	t.Cleanup(func() { conn.Close(); peer.Close() })
	uConn, err := buildRealityUConn(conn, &utls.Config{ServerName: "example.com", InsecureSkipVerify: true, SessionTicketsDisabled: true}, fingerprint, realityConfig)
	if err != nil {
		t.Fatalf("build client hello: %v", err)
	}
	return uConn
}

func hasKeyShareExtension(t *testing.T, fingerprint UClientHelloID) bool {
	spec, err := utls.UTLSIdToSpec(fingerprint)
	if err != nil {
		t.Fatalf("UTLSIdToSpec(%v): %v", fingerprint.Str(), err)
	}
	for _, extension := range spec.Extensions {
		if _, ok := extension.(*utls.KeyShareExtension); ok {
			return true
		}
	}
	return false
}

func TestRealityClientHelloX25519MLKEM768(t *testing.T) {
	for name, fingerprint := range fingerprints {
		if name == "random" || strings.Contains(name, "psk") {
			continue // the PSK fingerprints never worked with REALITY: utls refuses their empty PSK extension
		}
		if !hasKeyShareExtension(t, fingerprint) {
			continue // TLS 1.2 only fingerprints can't be used for REALITY anyway
		}
		t.Run(name, func(t *testing.T) {
			uConn := buildTestRealityHello(t, fingerprint, &RealityConfig{})
			hello := uConn.HandshakeState.Hello
			if !checkRealityKeyShares(hello.KeyShares) {
				t.Fatalf("client hello would be rejected by REALITY: %v", hello.KeyShares)
			}
			if mlkemIndex, x25519Index := curveIndex(hello.SupportedCurves, utls.X25519MLKEM768), curveIndex(hello.SupportedCurves, utls.X25519); mlkemIndex < 0 || (x25519Index >= 0 && mlkemIndex > x25519Index) {
				t.Fatalf("supported groups without X25519MLKEM768 before X25519: %v", hello.SupportedCurves)
			}
			for _, curve := range hello.SupportedCurves {
				if curve == utls.X25519Kyber768Draft00 {
					t.Fatalf("supported groups still have X25519Kyber768Draft00: %v", hello.SupportedCurves)
				}
			}
			// the key share must be backed by real keys
			keys := uConn.HandshakeState.State13.KeyShareKeys
			if keys == nil || keys.Mlkem == nil || keys.MlkemEcdhe == nil {
				t.Fatal("no X25519MLKEM768 private keys")
			}
			for _, keyShare := range hello.KeyShares {
				if keyShare.Group == utls.X25519MLKEM768 {
					if !bytes.Equal(keyShare.Data[:mlkem768EncapsulationKeySize], keys.Mlkem.EncapsulationKey().Bytes()) ||
						!bytes.Equal(keyShare.Data[mlkem768EncapsulationKeySize:], keys.MlkemEcdhe.PublicKey().Bytes()) {
						t.Fatal("X25519MLKEM768 key share does not match its private keys")
					}
				}
				if keyShare.Group == utls.X25519 && (keys.Ecdhe == nil || !bytes.Equal(keyShare.Data, keys.Ecdhe.PublicKey().Bytes())) {
					t.Fatal("X25519 key share does not match its private key")
				}
			}
			if len(hello.SessionId) != 32 || !bytes.Equal(hello.Raw[39:39+32], hello.SessionId) {
				t.Fatal("unexpected session ID location")
			}
		})
	}
}

// The real post-quantum parrots go out untouched, the classical ones get a key share injected
// (android and 360 are TLS 1.2 only fingerprints without key_share, unusable for REALITY).
func TestRealityClientHelloParrots(t *testing.T) {
	for _, name := range []string{"chrome", "firefox", "safari", "hellofirefox_148", "hellosafari_26_3", "hellochrome_131"} {
		fingerprint := fingerprints[name]
		uConn := buildTestRealityHello(t, fingerprint, &RealityConfig{})
		if uConn.ClientHelloID != fingerprint {
			t.Errorf("%s: client hello of %v is modified, got %v", name, fingerprint.Str(), uConn.ClientHelloID.Str())
		}
	}
	for _, name := range []string{"ios", "edge", "qq", "firefox120", "safari16", "chrome_pq"} {
		uConn := buildTestRealityHello(t, fingerprints[name], &RealityConfig{})
		if uConn.ClientHelloID != utls.HelloCustom {
			t.Errorf("%s: no X25519MLKEM768 key share is injected", name)
		}
	}
	if fingerprints["firefox"] != utls.HelloFirefox_148 || fingerprints["safari"] != utls.HelloSafari_26_3 {
		t.Error("firefox and safari are not the post-quantum parrots")
	}
	// Firefox 148 reuses the X25519 key of its X25519MLKEM768 key share for the X25519 one
	hello := buildTestRealityHello(t, utls.HelloFirefox_148, &RealityConfig{}).HandshakeState.Hello
	var hybrid, x25519 []byte
	for _, keyShare := range hello.KeyShares {
		switch keyShare.Group {
		case utls.X25519MLKEM768:
			hybrid = keyShare.Data
		case utls.X25519:
			x25519 = keyShare.Data
		}
	}
	if len(hybrid) != x25519MLKEM768KeyShareSize || !bytes.Equal(hybrid[mlkem768EncapsulationKeySize:], x25519) {
		t.Error("Firefox 148 does not reuse its X25519 key")
	}
}

func TestRealityClientHelloDisableX25519MLKEM768(t *testing.T) {
	for _, fingerprint := range []UClientHelloID{utls.HelloChrome_Auto, utls.HelloFirefox_Auto, utls.HelloChrome_120_PQ} {
		uConn := buildTestRealityHello(t, fingerprint, &RealityConfig{DisableX25519MLKEM768: true})
		hello := uConn.HandshakeState.Hello
		for _, keyShare := range hello.KeyShares {
			if keyShare.Group == utls.X25519MLKEM768 {
				t.Fatalf("%v: X25519MLKEM768 key share is not removed", fingerprint.Str())
			}
		}
		if curveIndex(hello.SupportedCurves, utls.X25519MLKEM768) >= 0 {
			t.Fatalf("%v: X25519MLKEM768 is not removed from supported groups", fingerprint.Str())
		}
	}
}

func curveIndex(curves []utls.CurveID, curve utls.CurveID) int {
	for i, c := range curves {
		if c == curve {
			return i
		}
	}
	return -1
}

func TestParseRealityClientVersion(t *testing.T) {
	for _, tt := range []struct {
		version string
		want    [3]byte
		ok      bool
	}{
		{RealityDefaultClientVersion, [3]byte{26, 10, 10}, true},
		{"1.8.2", [3]byte{1, 8, 2}, true},
		{"25.1", [3]byte{25, 1, 0}, true},
		{"255.255.255", [3]byte{255, 255, 255}, true},
		{"256.0.0", [3]byte{}, false},
		{"1.2.3.4", [3]byte{}, false},
		{"v1.8.2", [3]byte{}, false},
		{"", [3]byte{}, false},
	} {
		got, err := ParseRealityClientVersion(tt.version)
		if (err == nil) != tt.ok || (tt.ok && got != tt.want) {
			t.Errorf("ParseRealityClientVersion(%q) = %v, %v", tt.version, got, err)
		}
	}
}

// TestRealityMldsa65Interop checks that github.com/metacubex/mldsa derives the same ML-DSA-65 key from
// a seed and makes the same deterministic signature as github.com/cloudflare/circl, which Xray uses
// (mldsa65.NewKeyFromSeed for `mldsa65Seed`, mldsa65.SignTo(key, msg, nil, false, sig) in REALITY).
// The expected hashes were produced by circl v1.6.5.
func TestRealityMldsa65Interop(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := key.PublicKey().Bytes()
	if hash := sha256.Sum256(publicKey); hex.EncodeToString(hash[:]) != "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9" {
		t.Fatalf("public key differs from circl's: %x", hash)
	}
	message := []byte("REALITY ML-DSA-65 interop vector")
	signature, err := key.SignDeterministic(message, &mldsa.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if hash := sha256.Sum256(signature); hex.EncodeToString(hash[:]) != "7fe42e182bc582e0937d8a91773657bc1ca6b5342cb028c4e3cf461f42950599" {
		t.Fatalf("signature differs from circl's: %x", hash)
	}
	verify, err := ParseRealityMldsa65Verify(base64.RawURLEncoding.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	if !verify.Equal(key.PublicKey()) {
		t.Fatal("parsed public key differs")
	}
	if _, err = ParseRealityMldsa65Verify(base64.RawURLEncoding.EncodeToString(publicKey[1:])); err == nil {
		t.Fatal("short public key accepted")
	}
	if _, err = ParseRealityMldsa65Verify(base64.StdEncoding.EncodeToString(publicKey)); err == nil {
		t.Fatal("padded base64 accepted")
	}
}

// realityTestCertificate reproduces how the Xray REALITY server (handshake_server_tls13.go) makes
// its temporary certificate: an ed25519 certificate whose signature is replaced with
// HMAC-SHA512(authKey, public key) and, with `mldsa65Seed`, an extension at a fixed location
// holding the ML-DSA-65 signature of HMAC-SHA512(authKey, public key || client hello || server hello).
func realityTestCertificate(t *testing.T, authKey []byte, mldsa65Key *mldsa.PrivateKey, clientHello, serverHello []byte) *x509.Certificate {
	t.Helper()
	template := x509.Certificate{SerialNumber: &big.Int{}}
	if mldsa65Key != nil {
		template.ExtraExtensions = []pkix.Extension{{Id: []int{0, 0}, Value: make([]byte, mldsa.MLDSA65SignatureSize)}}
	}
	_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, ed25519Priv.Public(), ed25519Priv)
	if err != nil {
		t.Fatal(err)
	}
	h := hmac.New(sha512.New, authKey)
	h.Write(ed25519Priv[32:])
	h.Sum(cert[:len(cert)-64])
	if mldsa65Key != nil {
		h.Write(clientHello)
		h.Write(serverHello)
		signature, err := mldsa65Key.SignDeterministic(h.Sum(nil), &mldsa.Options{})
		if err != nil {
			t.Fatal(err)
		}
		copy(cert[126:], signature) // fixed location
	}
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestRealityVerifyCertificate(t *testing.T) {
	authKey := make([]byte, 32)
	clientHello := []byte("client hello")
	serverHello := []byte("server hello")
	_, _ = rand.Read(authKey)
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	mldsa65Key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}

	cert := realityTestCertificate(t, authKey, nil, nil, nil)
	if !realityVerifyCertificate(cert, authKey, nil, clientHello, serverHello) {
		t.Fatal("REALITY certificate is not verified")
	}
	if realityVerifyCertificate(cert, make([]byte, 32), nil, clientHello, serverHello) {
		t.Fatal("REALITY certificate is verified with a wrong auth key")
	}
	if realityVerifyCertificate(cert, authKey, mldsa65Key.PublicKey(), clientHello, serverHello) {
		t.Fatal("REALITY certificate without ML-DSA-65 signature is verified with mldsa65-verify")
	}

	cert = realityTestCertificate(t, authKey, mldsa65Key, clientHello, serverHello)
	if !bytes.Equal(cert.Extensions[0].Value[:16], cert.Raw[126:126+16]) {
		t.Fatal("unexpected ML-DSA-65 signature location")
	}
	if !realityVerifyCertificate(cert, authKey, mldsa65Key.PublicKey(), clientHello, serverHello) {
		t.Fatal("ML-DSA-65 signature is not verified")
	}
	if !realityVerifyCertificate(cert, authKey, nil, clientHello, serverHello) {
		t.Fatal("REALITY certificate with ML-DSA-65 signature is not verified without mldsa65-verify")
	}
	if realityVerifyCertificate(cert, authKey, otherKey.PublicKey(), clientHello, serverHello) {
		t.Fatal("ML-DSA-65 signature is verified with a wrong public key")
	}
	if realityVerifyCertificate(cert, authKey, mldsa65Key.PublicKey(), []byte("other client hello"), serverHello) {
		t.Fatal("ML-DSA-65 signature is verified for another client hello")
	}
	if realityVerifyCertificate(cert, authKey, mldsa65Key.PublicKey(), clientHello, []byte("other server hello")) {
		t.Fatal("ML-DSA-65 signature is verified for another server hello")
	}
}

// TestRealityHandshake runs the client against the REALITY server of utls with a local TLS 1.3 target,
// which signs with ML-DSA-65 and requires an X25519MLKEM768 key share like Xray v26.9.8+ servers.
func TestRealityHandshake(t *testing.T) {
	const serverName = "example.com"
	target := newTestTLSTarget(t, serverName)

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	mldsa65Seed := make([]byte, utls.RealityMldsa65SeedSize)
	_, _ = rand.Read(mldsa65Seed)
	mldsa65VerifyBytes, err := utls.RealityMldsa65Verify(mldsa65Seed)
	if err != nil {
		t.Fatal(err)
	}
	mldsa65Verify, err := ParseRealityMldsa65Verify(base64.RawURLEncoding.EncodeToString(mldsa65VerifyBytes))
	if err != nil {
		t.Fatal(err)
	}
	otherSeed := make([]byte, utls.RealityMldsa65SeedSize)
	otherVerifyBytes, _ := utls.RealityMldsa65Verify(otherSeed)
	otherVerify, _ := ParseRealityMldsa65Verify(base64.RawURLEncoding.EncodeToString(otherVerifyBytes))
	serverConfig := &utls.RealityConfig{
		DialContext:           (&net.Dialer{}).DialContext,
		Type:                  "tcp",
		Dest:                  target,
		ServerNames:           map[string]bool{serverName: true},
		PrivateKey:            privateKey.Bytes(),
		MinClientVer:          []byte{26, 10, 10},
		ShortIds:              map[[8]byte]bool{shortID: true},
		Mldsa65Seed:           mldsa65Seed,
		RequireX25519MLKEM768: true,
	}
	serverConfig.SessionTicketsDisabled = true
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				tlsConn, err := utls.RealityServer(context.Background(), conn, serverConfig)
				if err != nil {
					return
				}
				_, _ = tlsConn.Write([]byte("REALITY"))
				_, _ = io.Copy(io.Discard, tlsConn)
			}()
		}
	}()

	dial := func(fingerprint UClientHelloID, clientVersion string, verify *mldsa.PublicKey) error {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			return err
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		realityConfig := &RealityConfig{PublicKey: privateKey.PublicKey(), ShortID: shortID, Mldsa65Verify: verify}
		if realityConfig.ClientVersion, err = ParseRealityClientVersion(clientVersion); err != nil {
			return err
		}
		tlsConn, err := GetRealityConn(ctx, conn, fingerprint, serverName, realityConfig)
		if err != nil {
			return err
		}
		buf := make([]byte, 7)
		if _, err = io.ReadFull(tlsConn, buf); err != nil {
			return err
		}
		if string(buf) != "REALITY" {
			t.Errorf("unexpected data %q", buf)
		}
		return nil
	}
	// every fingerprint usable for REALITY passes the X25519MLKEM768 requirement
	for name, fingerprint := range fingerprints {
		if name == "random" || strings.Contains(name, "psk") || !hasKeyShareExtension(t, fingerprint) {
			continue // see TestRealityClientHelloX25519MLKEM768
		}
		if err = dial(fingerprint, RealityDefaultClientVersion, mldsa65Verify); err != nil {
			t.Errorf("%s (%v): %v", name, fingerprint.Str(), err)
		}
	}
	if err = dial(utls.HelloFirefox_Auto, RealityDefaultClientVersion, nil); err != nil {
		t.Errorf("without mldsa65-verify: %v", err)
	}
	if err = dial(utls.HelloChrome_Auto, RealityDefaultClientVersion, otherVerify); err == nil {
		t.Error("wrong mldsa65-verify is accepted")
	}
	if err = dial(utls.HelloChrome_Auto, "1.8.2", mldsa65Verify); err == nil {
		t.Error("client version below minClientVer is accepted")
	}
}

func newTestTLSTarget(t *testing.T, serverName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	// a chain as long as a real site's one, so that the ML-DSA-65 signature (3309 bytes) of
	// the REALITY server fits in the size of the target's Certificate message
	paddingTemplate := x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "padding"},
		NotBefore:       template.NotBefore,
		NotAfter:        template.NotAfter,
		ExtraExtensions: []pkix.Extension{{Id: []int{1, 3, 9999, 1}, Value: make([]byte, 4096)}},
	}
	padding, err := x509.CreateCertificate(rand.Reader, &paddingTemplate, &paddingTemplate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := stdtls.Listen("tcp", "127.0.0.1:0", &stdtls.Config{
		Certificates: []stdtls.Certificate{{Certificate: [][]byte{cert, padding}, PrivateKey: key}},
		MinVersion:   stdtls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.(*stdtls.Conn).Handshake()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return listener.Addr().String()
}
