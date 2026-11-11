// Package catest gives tests of the core's TLS clients a private root and a server certificate signed
// by it, so they can check that a client verifies against the pool of component/ca.
package catest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"

	"github.com/metacubex/tls"
)

// ServerName is the name the server certificate is issued for.
const ServerName = "catest.example.test"

type PKI struct {
	RootPEM string
	Leaf    tls.Certificate // for ServerName and 127.0.0.1
}

// New returns a root that no pool has and a server certificate signed by it.
func New(t testing.TB) *PKI {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Citrus catest Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: ServerName},
		DNSNames:     []string{ServerName},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return &PKI{
		RootPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})),
		Leaf:    tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
	}
}

// Trust installs the default roots with the root of p as a tls.custom-certifactes entry for the
// duration of the test.
func (p *PKI) Trust(t testing.TB) {
	t.Helper()
	roots, errs := ca.NewRoots(ca.RootPolicy{}, []string{p.RootPEM})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	prev := ca.SwapRoots(roots)
	t.Cleanup(func() { ca.SwapRoots(prev) })
}

// Handshake runs a TLS handshake of a client with config against a server holding the leaf of p.
func (p *PKI) Handshake(t testing.TB, config *tls.Config) error {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		server := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{p.Leaf}})
		_ = server.HandshakeContext(ctx)
		_ = serverConn.Close()
	}()
	return tls.Client(clientConn, config).HandshakeContext(ctx)
}
