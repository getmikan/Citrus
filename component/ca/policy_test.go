package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const policyServerName = "policy.example.test"

type testPKI struct {
	root    *x509.Certificate
	rootPEM string
	leaf    tls.Certificate
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Citrus Test Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: policyServerName},
		DNSNames:     []string{policyServerName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, root, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	return &testPKI{
		root:    root,
		rootPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})),
		leaf:    tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
	}
}

// denylist puts the test root on the denylist for the duration of the test.
func (p *testPKI) denylist(t *testing.T) {
	hash := spkiHash(p.root)
	denylistedSPKI[hash] = "Citrus Test Root"
	t.Cleanup(func() { delete(denylistedSPKI, hash) })
}

// handshake runs a TLS handshake of a client built by GetTLSConfig against a server holding the leaf.
func (p *testPKI) handshake(t *testing.T, opt Option) error {
	t.Helper()
	if opt.TLSConfig == nil {
		opt.TLSConfig = &tls.Config{}
	}
	opt.TLSConfig.ServerName = policyServerName
	clientConfig, err := GetTLSConfig(opt)
	require.NoError(t, err)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		server := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{p.leaf}})
		_ = server.HandshakeContext(ctx)
		_ = serverConn.Close()
	}()
	return tls.Client(clientConn, clientConfig).HandshakeContext(ctx)
}

// usePolicy installs the policy and bundle for the test and puts the defaults back afterwards.
func usePolicy(t *testing.T, policy RootPolicy, bundle []byte) {
	t.Cleanup(func() {
		bundlePEM = _CaCertificates
		SetRootPolicy(RootPolicy{})
		ResetCertificate()
	})
	bundlePEM = bundle
	SetRootPolicy(policy)
	ResetCertificate()
}

func TestParseRootSource(t *testing.T) {
	for in, want := range map[string]RootSource{"": RootsBoth, "both": RootsBoth, "Bundle": RootsBundle, " system ": RootsSystem} {
		got, err := ParseRootSource(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
		if in != "" {
			assert.Equal(t, want.String(), got.String())
		}
	}
	_, err := ParseRootSource("builtin")
	assert.Error(t, err)
}

func TestDenylistKnownRoots(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "denylist", "*.pem"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, file := range files {
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		certs := parseCertificates(data)
		require.Len(t, certs, 1, file)
		assert.NotEmpty(t, denylistedName(certs[0]), "%s (%s) is not denylisted", file, certs[0].Subject)
	}
}

func TestEmbeddedBundle(t *testing.T) {
	certs := parseCertificates(_CaCertificates)
	// The Mozilla store holds about 150 server roots, a short bundle means a broken refresh.
	require.Greater(t, len(certs), 100, "ca-certificates.crt must be committed, run make ca-bundle")
	for _, cert := range certs {
		assert.Empty(t, denylistedName(cert), "the bundle has the denylisted %s", cert.Subject)
	}
	assert.NotNil(t, zeroTrustCertPool())
}

func TestDenylistedBundledRootRejected(t *testing.T) {
	pki := newTestPKI(t)
	pki.denylist(t)
	usePolicy(t, RootPolicy{Source: RootsBundle}, []byte(pki.rootPEM))

	// left out of the bundled pool, so the chain does not verify at all
	err := pki.handshake(t, Option{})
	var unknown x509.UnknownAuthorityError
	assert.ErrorAs(t, err, &unknown)

	usePolicy(t, RootPolicy{Source: RootsBundle, DisableDenylist: true}, []byte(pki.rootPEM))
	assert.NoError(t, pki.handshake(t, Option{}))
}

func TestDenylistedSystemRootRejected(t *testing.T) {
	pki := newTestPKI(t)
	pki.denylist(t)
	// A root the system pool has: the pool cannot be filtered, the check runs after the verification.
	addSystemRoot := func() { GetCertPool().AddCert(pki.root) }

	usePolicy(t, RootPolicy{}, nil)
	addSystemRoot()
	var distrusted *DistrustedError
	require.ErrorAs(t, pki.handshake(t, Option{}), &distrusted)
	assert.Equal(t, "Citrus Test Root", distrusted.Name)
	assert.ErrorAs(t, pki.handshake(t, Option{NameCertVerify: policyServerName}), &distrusted)

	// a caller's own VerifyConnection runs after the check, and only when it passes
	called := false
	callerVerify := func(tls.ConnectionState) error {
		called = true
		return nil
	}
	assert.ErrorAs(t, pki.handshake(t, Option{TLSConfig: &tls.Config{VerifyConnection: callerVerify}}), &distrusted)
	assert.False(t, called)

	// pinning and skip-cert-verify trust the server explicitly
	assert.NoError(t, pki.handshake(t, Option{Fingerprint: CalculateFingerprint(pki.leaf.Certificate[0])}))
	assert.NoError(t, pki.handshake(t, Option{TLSConfig: &tls.Config{InsecureSkipVerify: true}}))

	usePolicy(t, RootPolicy{DisableDenylist: true}, nil)
	addSystemRoot()
	assert.NoError(t, pki.handshake(t, Option{}))
	assert.NoError(t, pki.handshake(t, Option{NameCertVerify: policyServerName}))
	assert.NoError(t, pki.handshake(t, Option{TLSConfig: &tls.Config{VerifyConnection: callerVerify}}))
	assert.True(t, called, "the caller's VerifyConnection is wrapped, not replaced")

	// and its error is returned
	callerErr := errors.New("caller")
	assert.ErrorIs(t, pki.handshake(t, Option{TLSConfig: &tls.Config{VerifyConnection: func(tls.ConnectionState) error {
		return callerErr
	}}}), callerErr)
}

func TestCustomCertificateExemptFromDenylist(t *testing.T) {
	pki := newTestPKI(t)
	pki.denylist(t)
	usePolicy(t, RootPolicy{}, nil)
	// tls.custom-certifactes is an explicit choice, it wins over the denylist
	require.NoError(t, AddCertificate(pki.rootPEM))
	assert.NoError(t, pki.handshake(t, Option{}))
	assert.NoError(t, pki.handshake(t, Option{NameCertVerify: policyServerName}))

	// and is forgotten on reload
	ResetCertificate()
	GetCertPool().AddCert(pki.root)
	var distrusted *DistrustedError
	assert.ErrorAs(t, pki.handshake(t, Option{}), &distrusted)
}

func TestCustomCertificateWithBundleOnly(t *testing.T) {
	pki := newTestPKI(t)
	usePolicy(t, RootPolicy{Source: RootsBundle}, _CaCertificates)
	var unknown x509.UnknownAuthorityError
	require.ErrorAs(t, pki.handshake(t, Option{}), &unknown)

	require.NoError(t, AddCertificate(pki.rootPEM))
	assert.NoError(t, pki.handshake(t, Option{}))
}

func TestRootSourcePools(t *testing.T) {
	bundled := x509.NewCertPool()
	require.Greater(t, appendBundle(bundled, true), 100)
	system, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("no system pool: %v", err)
	}
	both, _ := x509.SystemCertPool()
	appendBundle(both, true)

	usePolicy(t, RootPolicy{Source: RootsBundle}, _CaCertificates)
	assert.True(t, GetCertPool().Equal(bundled), "bundle must ignore the system pool")
	assert.False(t, GetCertPool().Equal(both))

	usePolicy(t, RootPolicy{Source: RootsSystem}, _CaCertificates)
	assert.True(t, GetCertPool().Equal(system), "system must ignore the bundle")

	if !DisableSystemCa && !DisableEmbedCa {
		usePolicy(t, RootPolicy{}, _CaCertificates)
		assert.True(t, GetCertPool().Equal(both))
	}
}

func TestCheckChains(t *testing.T) {
	pki := newTestPKI(t)
	pki.denylist(t)
	usePolicy(t, RootPolicy{}, nil)

	clean := []*x509.Certificate{leafCert, intermediateCert, rootCert}
	distrusted := []*x509.Certificate{leafCert, pki.root}
	assert.NoError(t, CheckChains(nil))
	assert.NoError(t, CheckChains([][]*x509.Certificate{clean}))
	// one clean chain is enough, a cross-signed server keeps working
	assert.NoError(t, CheckChains([][]*x509.Certificate{distrusted, clean}))
	err := CheckChains([][]*x509.Certificate{distrusted})
	var target *DistrustedError
	assert.True(t, errors.As(err, &target))
}

func TestNewRootsAndSwap(t *testing.T) {
	pki := newTestPKI(t)
	pki.denylist(t)
	usePolicy(t, RootPolicy{}, nil)
	installed := GetCertPool()

	roots, errs := NewRoots(RootPolicy{Source: RootsBundle}, []string{pki.rootPEM, "not a certificate"})
	assert.Len(t, errs, 1)
	// built, not installed yet
	assert.Same(t, installed, GetCertPool())

	prev := SwapRoots(roots)
	assert.Same(t, roots.pool, GetCertPool())
	// the custom root is trusted and exempt from the denylist
	assert.NoError(t, pki.handshake(t, Option{}))

	SwapRoots(prev)
	assert.Same(t, installed, GetCertPool())
	var unknown x509.UnknownAuthorityError
	assert.ErrorAs(t, pki.handshake(t, Option{}), &unknown)

	// nil is the default policy, built by the next GetCertPool
	SwapRoots(nil)
	assert.Equal(t, RootPolicy{}, rootPolicy)
	assert.NotNil(t, GetCertPool())
}
