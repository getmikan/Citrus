package ca

import (
	"crypto/x509"
	"errors"
	"time"
)

// NewNameCertVerifier returns a verifier for a certificate chain and an explicit DNSName.
// Like Xray's `verifyPeerCertByName`, dnsName can be a comma-separated list, any of them matching is enough.
func NewNameCertVerifier(dnsName string, roots *x509.CertPool, now func() time.Time) func([]*x509.Certificate) error {
	dnsNames := splitList(dnsName)
	if len(dnsNames) == 0 {
		dnsNames = []string{dnsName}
	}
	return func(certificates []*x509.Certificate) (err error) {
		if len(certificates) == 0 {
			return errors.New("tls: no peer certificates")
		}

		intermediates := x509.NewCertPool()
		for _, certificate := range certificates[1:] {
			intermediates.AddCert(certificate)
		}
		verifyOptions := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
		}
		if now != nil {
			verifyOptions.CurrentTime = now()
		}
		for _, verifyOptions.DNSName = range dnsNames {
			if _, err = certificates[0].Verify(verifyOptions); err == nil {
				return nil
			}
		}
		return err
	}
}
