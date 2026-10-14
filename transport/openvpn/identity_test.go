package openvpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/metacubex/tls"
	"math/big"
	"net"
	"testing"
	"time"
)

type testPKI struct {
	caPEM []byte
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Easy-RSA CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return &testPKI{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca: ca, caKey: key}
}

func (p *testPKI) issue(t *testing.T, subject pkix.Name, dns []string, ips []net.IP) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func verifyWith(t *testing.T, cfg *ClientConfig, leaf *x509.Certificate) error {
	t.Helper()
	tlsCfg, err := (&Client{config: cfg}).tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	return tlsCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}})
}

func TestServerIdentity(t *testing.T) {
	pki := newTestPKI(t)
	server := pki.issue(t, pkix.Name{CommonName: "server_abc", Organization: []string{"VPN"}}, nil, nil)
	other := pki.issue(t, pkix.Name{CommonName: "client1"}, nil, nil)
	named := pki.issue(t, pkix.Name{CommonName: "vpn.example.com"}, []string{"vpn.example.com"}, []net.IP{net.ParseIP("192.0.2.1")})

	base := ClientConfig{RemoteHost: "192.0.2.1", RemotePort: 1194, Proto: ProtoUDP, Username: "u", CA: pki.caPEM}
	tests := []struct {
		name     string
		x509Name string
		x509Type string
		strict   bool
		leaf     *x509.Certificate
		ok       bool
	}{
		{"ca only accepts any server cert", "", "", false, other, true},
		{"name matches", "server_abc", "name", false, server, true},
		{"name mismatch", "server_abc", "name", false, other, false},
		{"name-prefix matches", "server_", "name-prefix", false, server, true},
		{"name-prefix mismatch", "server_", "name-prefix", false, other, false},
		{"subject matches in any order", "CN=server_abc, O=VPN", "", false, server, true},
		{"subject must be complete", "CN=server_abc", "subject", false, server, false},
		{"server name by IP SAN", "", "", true, named, true},
		{"server name mismatch", "", "", true, server, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			cfg.VerifyX509Name = tt.x509Name
			cfg.VerifyX509Type = tt.x509Type
			cfg.VerifyServerName = tt.strict
			if err := cfg.Prepare(); err != nil {
				t.Fatal(err)
			}
			if got := cfg.ChecksServerIdentity(); got != (tt.x509Name != "" || tt.strict) {
				t.Fatalf("ChecksServerIdentity = %v", got)
			}
			err := verifyWith(t, &cfg, tt.leaf)
			if (err == nil) != tt.ok {
				t.Fatalf("ok=%v, err=%v", tt.ok, err)
			}
		})
	}
}

func TestServerIdentityConfigErrors(t *testing.T) {
	for _, tt := range []struct{ name, typ string }{
		{"server", ""},           // bare name with the default subject type
		{"server", "commonname"}, // unknown type
		{"", "name"},             // type without name
	} {
		cfg := ClientConfig{RemoteHost: "192.0.2.1", RemotePort: 1194, Proto: ProtoUDP, Username: "u", VerifyX509Name: tt.name, VerifyX509Type: tt.typ}
		if err := cfg.Prepare(); err == nil {
			t.Errorf("accepted verify-x509-name %q type %q", tt.name, tt.typ)
		}
	}
}
