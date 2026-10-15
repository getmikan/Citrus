package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"
)

// Sink commands: the first byte a client sends through the proxy.
const (
	cmdEcho     = 'E' // echo everything back, forever (idle connections)
	cmdDownload = 'D' // the sink writes as fast as it can
	cmdUpload   = 'U' // the sink reads and discards
	cmdRequest  = 'R' // the sink answers rateReplySize bytes and closes first
)

const rateReplySize = 64

// startSink runs the destination of every proxied connection, a plain TCP
// server on loopback. In request mode the sink closes first, so TIME_WAIT
// lands on the listening side, not on an ephemeral port.
func startSink() (net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSink(c)
		}
	}()
	return ln, nil
}

func handleSink(c net.Conn) {
	defer c.Close()
	var cmd [1]byte
	if _, err := io.ReadFull(c, cmd[:]); err != nil {
		return
	}
	switch cmd[0] {
	case cmdEcho:
		io.Copy(c, c)
	case cmdDownload:
		buf := make([]byte, 32*1024)
		rand.Read(buf)
		for {
			if _, err := c.Write(buf); err != nil {
				return
			}
		}
	case cmdUpload:
		io.Copy(io.Discard, c)
	case cmdRequest:
		var reply [rateReplySize]byte
		c.Write(reply[:])
	}
}

// startRealityDest runs the REALITY target: a TLS 1.3 server that only
// completes handshakes. The REALITY server contacts it on every connection.
func startRealityDest(cert tls.Certificate) (net.Listener, error) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(30 * time.Second))
				if err := c.(*tls.Conn).Handshake(); err != nil {
					return
				}
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln, nil
}

// --- key material -------------------------------------------------------------

type material struct {
	certPEM, keyPEM string
	cert            tls.Certificate
	realityPriv     string // base64url, no padding
	realityPub      string
	shortID         string
	uuid            string
	password        string
	ssServerPSK     string // 2022-blake3-aes-128-gcm iPSK
	ssUserPSK       string
}

const benchSNI = "bench.test"

func newMaterial() (*material, error) {
	m := &material{}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: benchSNI},
		DNSNames:     []string{benchSNI},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	m.certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	m.keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
	if m.cert, err = tls.X509KeyPair([]byte(m.certPEM), []byte(m.keyPEM)); err != nil {
		return nil, err
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	m.realityPriv = base64.RawURLEncoding.EncodeToString(priv.Bytes())
	m.realityPub = base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	m.shortID = randHex(8)
	u := randBytes(16)
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	m.uuid = fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
	m.password = randHex(16)
	m.ssServerPSK = base64.StdEncoding.EncodeToString(randBytes(16))
	m.ssUserPSK = base64.StdEncoding.EncodeToString(randBytes(16))
	return m, nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func randHex(n int) string { return hex.EncodeToString(randBytes(n)) }
