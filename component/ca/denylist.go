package ca

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// denylistedSPKI holds roots and intermediates that the core never trusts for its own TLS verification,
// whichever pool (system or bundled) they come from. They are state-operated CAs that exist to intercept
// TLS, so trusting them would let the operator read and rewrite proxied traffic whenever such a CA is
// installed on the device. Entries are the SHA-256 of the DER SubjectPublicKeyInfo, so a re-issued
// certificate with the same key is caught as well.
//
// Sources:
//   - Russian Trusted Root CA and Sub CA: the official distribution by the Ministry of Digital Development,
//     https://www.gosuslugi.ru/crt (files russian_trusted_root_ca_pem.crt, russian_trusted_sub_ca_pem.crt
//     and russian_trusted_sub_ca_2024_pem.crt under https://gu-st.ru/content/lending/). The GOST 2025
//     roots are left out: Go cannot verify GOST R 34.10-2012 signatures, so they can never anchor a chain.
//   - Qaznet Trust Network and Information Security Certification Authority (Kazakhstan, 2019-2021):
//     Chromium's kSPKIBlockList, net/cert/cert_verify_proc_blocklist.inc, with the certificates in
//     net/data/ssl/blocklist/ ("Qaznet Trust Network" section of its README), see also
//     https://security.googleblog.com/2019/08/protecting-chrome-users-in-kazakhstan.html
//
// Every hash was recomputed from the certificate itself (testdata/denylist has some of them).
var denylistedSPKI = map[[sha256.Size]byte]string{
	// CN=Russian Trusted Root CA, O=The Ministry of Digital Development and Communications, C=RU (2022-2032)
	mustSPKI("02b8220c070728db771d9ac59e54521c4eddad21a783bb26cfdf19c1db0fae37"): "Russian Trusted Root CA",
	// CN=Russian Trusted Sub CA (2022-2027)
	mustSPKI("0447aa4b18c48b9e8db16e91809286dd27efd6a50ba80d3084eb9e70ba8e1dca"): "Russian Trusted Sub CA",
	// CN=Russian Trusted Sub CA (2024-2029)
	mustSPKI("37b95ae1738dc4c69661144715669fdb9c93e7adb3363422deb61c0f3acf65c1"): "Russian Trusted Sub CA (2024)",

	// CN=Qaznet Trust Network, C=KZ (2016-2046)
	mustSPKI("b5ba8dd7f89564c2889d3d6453c84998c77824919b64ea0835aa62986591be50"): "Qaznet Trust Network",
	// CN=Information Security Certification Authority, O=ISCA, C=KZ, the 2020 and 2021 interception roots
	mustSPKI("c56217b7a828c7341c0ae7a590d8790d4def536652e60ae5b8bdfa26978fe09c"): "Information Security Certification Authority (KZ)",
	mustSPKI("e47c5cd2dc8babb4e53f8a4983920275ef6ffaacb089e87a2c1fbe5a585f05ed"): "Information Security Certification Authority (KZ)",
	mustSPKI("39736588b94a4ce767f731cad53f4cbe44137e321eadcaef8ce79a229bbca989"): "Information Security Certification Authority (KZ)",
	mustSPKI("b13fa2e6131a888a01f3d62056fb0efbe999eb6b6e14927613e02ba8b8fb046e"): "Information Security Certification Authority (KZ)",
	mustSPKI("3472e4f16c570e0dd388aaaa4a64a34a4b939f1ca770996b5be0037c1aded9c1"): "Information Security Certification Authority (KZ)",
	mustSPKI("8928c59398b0f171c0f96fdae6ab8dd0f48ee06d174da10c404ac00143c7a749"): "Information Security Certification Authority (KZ)",
	mustSPKI("02a95f43431019e9dc225f05f419330190deb4a3f1869caac9842b403dcbee77"): "Information Security Certification Authority (KZ)",
	mustSPKI("ea12705de7c48f6fcce2cb8dbc542e0fc38ac38e08880dd04a02ef67c93ae135"): "Information Security Certification Authority (KZ)",
	// CN=Information Security Certification Authority CA, O=ISCA, C=KZ
	mustSPKI("8e12d0cb3b7df3ea2257579489fd8658c95603ea6cf4b73163a41eb7b7e93fee"): "Information Security Certification Authority CA (KZ)",
}

func mustSPKI(s string) (hash [sha256.Size]byte) {
	if b, err := hex.DecodeString(s); err != nil || len(b) != sha256.Size {
		panic("ca: bad denylist entry " + s)
	} else {
		copy(hash[:], b)
	}
	return
}

func spkiHash(cert *x509.Certificate) [sha256.Size]byte {
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

// denylistedName returns the name of the denylist entry matching cert, or "" when there is none.
func denylistedName(cert *x509.Certificate) string {
	return denylistedSPKI[spkiHash(cert)]
}

// DistrustedError is returned when every verified chain goes through a denylisted CA.
type DistrustedError struct {
	Name    string // the denylist entry
	Subject string // the certificate that matched it
}

func (e *DistrustedError) Error() string {
	return fmt.Sprintf("tls: certificate chain goes through the distrusted CA %q (%s); "+
		"add it to tls.custom-certifactes or set tls.ca-denylist: false to trust it", e.Name, e.Subject)
}

// CheckChains rejects verified chains that go through a denylisted CA. One clean chain is enough, so
// a server that is also cross-signed by a trusted root still works. A chain anchored at a certificate
// from tls.custom-certifactes is always clean: the user trusted that root explicitly. No chains (the
// verification was skipped or done by pinning) pass.
//
// Code that sets RootCAs to [GetCertPool] without going through [GetTLSConfig] calls this from its
// VerifyConnection, or on the chains returned by [x509.Certificate.Verify].
func CheckChains(chains [][]*x509.Certificate) error {
	if len(chains) == 0 {
		return nil
	}
	mutex.RLock()
	enabled, custom := !rootPolicy.DisableDenylist, customSPKI
	mutex.RUnlock()
	if !enabled {
		return nil
	}

	var distrusted *DistrustedError
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		if _, ok := custom[spkiHash(chain[len(chain)-1])]; ok {
			return nil
		}
		clean := true
		for _, cert := range chain {
			if name := denylistedName(cert); name != "" {
				if distrusted == nil {
					distrusted = &DistrustedError{Name: name, Subject: cert.Subject.String()}
				}
				clean = false
				break
			}
		}
		if clean {
			return nil
		}
	}
	if distrusted == nil {
		return nil
	}
	return distrusted
}
