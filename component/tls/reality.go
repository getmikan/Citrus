package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"

	"github.com/metacubex/http"
	"github.com/metacubex/mldsa"
	"github.com/metacubex/randv2"
	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
)

const RealityMaxShortIDLen = 8

// RealityDefaultClientVersion is the Xray-core version a REALITY client reports to the server
// by default, servers can reject clients outside their minClientVer..maxClientVer range.
const RealityDefaultClientVersion = "26.10.10"

type RealityConfig struct {
	PublicKey     *ecdh.PublicKey
	ShortID       [RealityMaxShortIDLen]byte
	ClientVersion [3]byte
	Mldsa65Verify *mldsa.PublicKey

	// DisableX25519MLKEM768 removes X25519MLKEM768 from the client hello, which only some old
	// REALITY servers need; Xray v26.9.8+ servers silently reject such a hello.
	DisableX25519MLKEM768 bool
}

// ParseRealityClientVersion parses an Xray version like "26.10.10" into the bytes of REALITY's session ID.
func ParseRealityClientVersion(version string) (clientVersion [3]byte, err error) {
	parts := strings.Split(version, ".")
	if len(parts) > len(clientVersion) {
		return clientVersion, fmt.Errorf("invalid REALITY client version: %s", version)
	}
	for i, part := range parts {
		n, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return clientVersion, fmt.Errorf("invalid REALITY client version: %s", version)
		}
		clientVersion[i] = byte(n)
	}
	return clientVersion, nil
}

// ParseRealityMldsa65Verify parses the base64url (unpadded) encoded ML-DSA-65 public key, same as Xray's `mldsa65Verify`.
func ParseRealityMldsa65Verify(publicKey string) (*mldsa.PublicKey, error) {
	key, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil || len(key) != mldsa.MLDSA65PublicKeySize {
		return nil, errors.New("invalid REALITY ML-DSA-65 public key")
	}
	return mldsa.NewPublicKey(mldsa.MLDSA65(), key)
}

func GetRealityConn(ctx context.Context, conn net.Conn, fingerprint UClientHelloID, serverName string, realityConfig *RealityConfig) (net.Conn, error) {
	for retry := 0; ; retry++ {
		verifier := &realityVerifier{
			serverName:    serverName,
			mldsa65Verify: realityConfig.Mldsa65Verify,
		}
		uConfig := &utls.Config{
			Time:                   ntp.Now,
			ServerName:             serverName,
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: true,
			VerifyConnection:       verifier.VerifyConnection,
		}

		uConn, err := buildRealityUConn(conn, uConfig, fingerprint, realityConfig)
		if err != nil {
			return nil, err
		}
		verifier.UConn = uConn

		hello := uConn.HandshakeState.Hello
		rawSessionID := hello.Raw[39 : 39+32] // the location of session ID
		for i := range rawSessionID {         // https://github.com/golang/go/issues/5373
			rawSessionID[i] = 0
		}

		binary.BigEndian.PutUint64(hello.SessionId, uint64(ntp.Now().Unix()))

		copy(hello.SessionId[8:], realityConfig.ShortID[:])
		copy(hello.SessionId[:3], realityConfig.ClientVersion[:])
		hello.SessionId[3] = 0 // reserved

		//log.Debugln("REALITY hello.sessionId[:16]: %v", hello.SessionId[:16])

		keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
		if keyShareKeys == nil {
			// WTF???
			if retry > 2 {
				return nil, errors.New("nil keyShareKeys")
			}
			continue // retry
		}
		ecdheKey := keyShareKeys.Ecdhe
		if ecdheKey == nil {
			ecdheKey = keyShareKeys.MlkemEcdhe
		}
		if ecdheKey == nil {
			// WTF???
			if retry > 2 {
				return nil, errors.New("nil ecdheKey")
			}
			continue // retry
		}
		authKey, err := ecdheKey.ECDH(realityConfig.PublicKey)
		if err != nil {
			return nil, err
		}
		if authKey == nil {
			return nil, errors.New("nil auth_key")
		}
		verifier.authKey = authKey
		_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
		if err != nil {
			return nil, err
		}
		aesBlock, _ := aes.NewCipher(authKey)
		aeadCipher, _ := cipher.NewGCM(aesBlock)
		aeadCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
		copy(hello.Raw[39:], hello.SessionId)
		//log.Debugln("REALITY hello.sessionId: %v", hello.SessionId)
		//log.Debugln("REALITY uConn.AuthKey: %v", authKey)

		err = uConn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}

		log.Debugln("REALITY Authentication: %v, AEAD: %T", verifier.verified, aeadCipher)

		if !verifier.verified {
			go realityClientFallback(uConn, uConfig.ServerName, fingerprint)
			return nil, errors.New("REALITY authentication failed")
		}

		return uConn, nil
	}
}

// buildRealityUConn builds the client hello. Since Xray v26.9.8 (XTLS/REALITY@8cdf7bf) the server
// drops any client hello without an X25519MLKEM768 key share placed before X25519, so one is
// injected for the fingerprints without it.
func buildRealityUConn(conn net.Conn, uConfig *utls.Config, fingerprint UClientHelloID, realityConfig *RealityConfig) (*utls.UConn, error) {
	if !realityConfig.DisableX25519MLKEM768 {
		return UClientWithX25519MLKEM768(conn, uConfig, fingerprint)
	}
	uConn := utls.UClient(conn, uConfig, fingerprint)
	// for X25519MLKEM768 does not work properly with the old reality server
	if err := BuildRemovedX25519MLKEM768HandshakeState(uConn); err != nil {
		return nil, err
	}
	return uConn, nil
}

func realityClientFallback(uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	// use h2c mode to disallow the net/http fallback to http1.1
	//
	// Note that this usage is only applicable to our own net/http fork.
	// The standard library also needs to mask the tls.Conn type for the conn returned by DialTLSContext
	// see: https://github.com/golang/go/issues/79293#issuecomment-4426393534
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	client := http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return uConn, nil
			},
			Protocols: protocols,
		},
	}
	request, err := http.NewRequest("GET", "https://"+serverName, nil)
	if err != nil {
		return
	}
	request.Header.Set("User-Agent", fingerprint.Client)
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", randv2.IntN(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	//_, _ = io.Copy(io.Discard, response.Body)
	time.Sleep(time.Duration(5+randv2.IntN(10)) * time.Second)
	response.Body.Close()
	client.CloseIdleConnections()
}

type realityVerifier struct {
	*utls.UConn
	serverName    string
	authKey       []byte
	mldsa65Verify *mldsa.PublicKey
	verified      bool
}

func (c *realityVerifier) VerifyConnection(state utls.ConnectionState) error {
	log.Debugln("REALITY localAddr: %v is using X25519MLKEM768 for TLS' communication: %v", c.RemoteAddr(), c.HandshakeState.ServerHello.ServerShare.Group == utls.X25519MLKEM768)
	certs := state.PeerCertificates
	if realityVerifyCertificate(certs[0], c.authKey, c.mldsa65Verify, c.HandshakeState.Hello.Raw, c.HandshakeState.ServerHello.Raw) {
		c.verified = true
		return nil
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   ntp.Now(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

// realityVerifyCertificate reports whether cert is the temporary certificate of the REALITY server
// holding authKey: its ed25519 "signature" is HMAC-SHA512(authKey, public key). With mldsa65Verify
// the certificate must also carry, in its first extension, the ML-DSA-65 signature of
// HMAC-SHA512(authKey, public key || client hello || server hello), like Xray's `mldsa65Verify`.
func realityVerifyCertificate(cert *x509.Certificate, authKey []byte, mldsa65Verify *mldsa.PublicKey, clientHello, serverHello []byte) bool {
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return false
	}
	h := hmac.New(sha512.New, authKey)
	h.Write(pub)
	if !bytes.Equal(h.Sum(nil), cert.Signature) {
		return false
	}
	if mldsa65Verify == nil {
		return true
	}
	if len(cert.Extensions) == 0 {
		return false
	}
	h.Write(clientHello)
	h.Write(serverHello)
	return mldsa.Verify(mldsa65Verify, h.Sum(nil), cert.Extensions[0].Value, nil) == nil
}
