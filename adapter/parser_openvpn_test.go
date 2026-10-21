package adapter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestParseProxyOpenVPNTLSVersionMin(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	mapping := func(version any) map[string]any {
		m := map[string]any{
			"name": "ovpn", "type": "openvpn", "server": "127.0.0.1", "port": 1194,
			"ca": ca, "username": "u", "password": "p", "skip-server-identity-check": true,
		}
		if version != nil {
			m["tls-version-min"] = version
		}
		return m
	}

	for _, version := range []any{nil, "1.2", "1.3"} {
		proxy, err := ParseProxy(mapping(version))
		if err != nil {
			t.Fatalf("tls-version-min %v: %v", version, err)
		}
		_ = proxy.Close()
	}

	_, err = ParseProxy(mapping("1.0"))
	if err == nil || !strings.Contains(err.Error(), "tls-version-min") {
		t.Fatalf("tls-version-min 1.0 accepted: %v", err)
	}
}
