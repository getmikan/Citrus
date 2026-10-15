package ca

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// NewFingerprintVerifier returns a function that verifies whether a certificate's SHA-256 fingerprint matches the given one.
// Like Xray's `pinnedPeerCertSha256`, fingerprint can be a comma-separated list, any of them matching is enough.
func NewFingerprintVerifier(fingerprint string, time func() time.Time) (func(certs []*x509.Certificate, serverName string) error, error) {
	var fpBytes [][]byte
	for _, fp := range splitList(fingerprint) {
		switch fp {
		case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized": // WTF???
			return nil, fmt.Errorf("`fingerprint` is used for TLS certificate pinning. If you need to specify the browser fingerprint, use `client-fingerprint`")
		}
		fpByte, err := hex.DecodeString(strings.Replace(fp, ":", "", -1))
		if err != nil {
			return nil, fmt.Errorf("fingerprint string decode error: %w", err)
		}

		if len(fpByte) != 32 {
			return nil, fmt.Errorf("fingerprint string length error,need sha256 fingerprint")
		}
		fpBytes = append(fpBytes, fpByte)
	}
	if len(fpBytes) == 0 {
		return nil, fmt.Errorf("fingerprint string length error,need sha256 fingerprint")
	}

	return func(certs []*x509.Certificate, serverName string) error {
		// ssl pining
		for i, cert := range certs {
			hash := sha256.Sum256(cert.Raw)
			if containsFingerprint(fpBytes, hash[:]) {
				if i > 0 {
					// When the fingerprint matches a non-leaf certificate,
					// the certificate chain validity is verified using the certificate as the trusted root certificate.
					opts := x509.VerifyOptions{
						Roots:         x509.NewCertPool(),
						Intermediates: x509.NewCertPool(),
						DNSName:       serverName,
					}
					if time != nil {
						opts.CurrentTime = time()
					}
					opts.Roots.AddCert(certs[i])
					for _, cert := range certs[1 : i+1] { // stop at i
						opts.Intermediates.AddCert(cert)
					}
					_, err := certs[0].Verify(opts)
					return err
				}
				return nil
			}
		}
		return errNotMatch
	}, nil
}

// NewFingerprintNameVerifier is NewFingerprintVerifier whose chain of a pinned non-leaf certificate is verified
// for any of the comma-separated names of `name-cert-verify`, or for the serverName when names is empty.
func NewFingerprintNameVerifier(fingerprint string, names string, time func() time.Time) (func(certs []*x509.Certificate, serverName string) error, error) {
	verifier, err := NewFingerprintVerifier(fingerprint, time)
	if err != nil {
		return nil, err
	}
	nameList := splitList(names)
	if len(nameList) == 0 {
		return verifier, nil
	}
	return func(certs []*x509.Certificate, _ string) (err error) {
		for _, name := range nameList {
			if err = verifier(certs, name); err == nil || errors.Is(err, errNotMatch) {
				return
			}
		}
		return
	}, nil
}

func containsFingerprint(fpBytes [][]byte, hash []byte) bool {
	for _, fpByte := range fpBytes {
		if bytes.Equal(fpByte, hash) {
			return true
		}
	}
	return false
}

// splitList splits a comma-separated list, dropping the empty items.
func splitList(s string) (list []string) {
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			list = append(list, item)
		}
	}
	return
}

// CalculateFingerprint computes the SHA-256 fingerprint of the given DER-encoded certificate and returns it as a hex string.
func CalculateFingerprint(certDER []byte) string {
	hash := sha256.Sum256(certDER)
	return hex.EncodeToString(hash[:])
}
