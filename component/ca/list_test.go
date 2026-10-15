package ca

import (
	"crypto/sha256"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFingerprintVerifierList(t *testing.T) {
	otherFingerprint := CalculateFingerprint(smimeRootCert.Raw)
	leafFingerprint := CalculateFingerprint(leafCert.Raw)
	intermediateFingerprint := CalculateFingerprint(intermediateCert.Raw)
	chain := []*x509.Certificate{leafCert, intermediateCert, rootCert}

	// any of the comma-separated pins matching is enough, like Xray's pinnedPeerCertSha256
	verifier, err := NewFingerprintVerifier(otherFingerprint+", "+leafFingerprint+",", certTime)
	require.NoError(t, err)
	assert.NoError(t, verifier(chain, wrongLeafServerName))

	verifier, err = NewFingerprintVerifier(otherFingerprint+","+intermediateFingerprint, certTime)
	require.NoError(t, err)
	assert.NoError(t, verifier(chain, leafServerName))
	assert.Error(t, verifier(chain, wrongLeafServerName))

	verifier, err = NewFingerprintVerifier(otherFingerprint, certTime)
	require.NoError(t, err)
	assert.ErrorIs(t, verifier(chain, leafServerName), errNotMatch)

	// OpenSSL format with colons
	hash := sha256.Sum256(leafCert.Raw)
	var colons []string
	for _, b := range hash {
		colons = append(colons, hexByte(b))
	}
	verifier, err = NewFingerprintVerifier(otherFingerprint+","+strings.Join(colons, ":"), certTime)
	require.NoError(t, err)
	assert.NoError(t, verifier(chain, ""))

	for _, fingerprint := range []string{"", ",", leafFingerprint + ",xyz", leafFingerprint + ",abcd", "chrome"} {
		_, err = NewFingerprintVerifier(fingerprint, certTime)
		assert.Error(t, err, fingerprint)
	}
}

func hexByte(b byte) string {
	const digits = "0123456789ABCDEF"
	return string([]byte{digits[b>>4], digits[b&0xf]})
}

func TestFingerprintNameVerifier(t *testing.T) {
	intermediateFingerprint := CalculateFingerprint(intermediateCert.Raw)
	chain := []*x509.Certificate{leafCert, intermediateCert, rootCert}

	verifier, err := NewFingerprintNameVerifier(intermediateFingerprint, wrongLeafServerName+","+leafServerName, certTime)
	require.NoError(t, err)
	assert.NoError(t, verifier(chain, wrongLeafServerName))

	verifier, err = NewFingerprintNameVerifier(intermediateFingerprint, wrongLeafServerName, certTime)
	require.NoError(t, err)
	assert.Error(t, verifier(chain, leafServerName))

	// no names: the server name is used
	verifier, err = NewFingerprintNameVerifier(intermediateFingerprint, " ", certTime)
	require.NoError(t, err)
	assert.NoError(t, verifier(chain, leafServerName))
	assert.Error(t, verifier(chain, wrongLeafServerName))

	verifier, err = NewFingerprintNameVerifier(CalculateFingerprint(smimeRootCert.Raw), leafServerName, certTime)
	require.NoError(t, err)
	assert.ErrorIs(t, verifier(chain, leafServerName), errNotMatch)
}

func TestNameCertVerifierList(t *testing.T) {
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	chain := []*x509.Certificate{leafCert, intermediateCert}

	// any of the comma-separated names matching is enough, like Xray's verifyPeerCertByName
	assert.NoError(t, NewNameCertVerifier(wrongLeafServerName+", "+leafServerName, roots, certTime)(chain))
	assert.NoError(t, NewNameCertVerifier(leafServerName+","+wrongLeafServerName, roots, certTime)(chain))
	assert.Error(t, NewNameCertVerifier(wrongLeafServerName+",example.com", roots, certTime)(chain))
}
