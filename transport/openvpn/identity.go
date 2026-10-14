package openvpn

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"sort"
	"strings"
)

// verify-x509-name types, as in OpenVPN.
const (
	X509NameSubject     = "subject"
	X509NameName        = "name"
	X509NamePrefix      = "name-prefix"
	defaultX509NameType = X509NameSubject
)

// prepareServerIdentity validates VerifyX509Name/VerifyX509Type.
func (c *ClientConfig) prepareServerIdentity() error {
	c.VerifyX509Name = strings.TrimSpace(c.VerifyX509Name)
	c.VerifyX509Type = strings.ToLower(strings.TrimSpace(c.VerifyX509Type))
	if c.VerifyX509Name == "" {
		if c.VerifyX509Type != "" {
			return fmt.Errorf("openvpn verify-x509-type %q needs verify-x509-name", c.VerifyX509Type)
		}
		return nil
	}
	if c.VerifyX509Type == "" {
		c.VerifyX509Type = defaultX509NameType
	}
	switch c.VerifyX509Type {
	case X509NameName, X509NamePrefix:
	case X509NameSubject:
		if _, err := parseOpenVPNSubject(c.VerifyX509Name); err != nil {
			return fmt.Errorf("openvpn verify-x509-name: %w (to match the common name only, set verify-x509-type: name)", err)
		}
	default:
		return fmt.Errorf("unsupported openvpn verify-x509-type %q: only subject, name and name-prefix are supported", c.VerifyX509Type)
	}
	return nil
}

// checkServerIdentity checks the server leaf certificate (whose chain is
// already verified against the CA) against verify-x509-name and, when
// VerifyServerName is set, against the remote host name or address.
func (c *ClientConfig) checkServerIdentity(leaf *x509.Certificate) error {
	if c.VerifyX509Name != "" {
		cn := leaf.Subject.CommonName
		switch c.VerifyX509Type {
		case X509NameName:
			if cn != c.VerifyX509Name {
				return fmt.Errorf("openvpn server certificate name %q does not match verify-x509-name %q", cn, c.VerifyX509Name)
			}
		case X509NamePrefix:
			if !strings.HasPrefix(cn, c.VerifyX509Name) {
				return fmt.Errorf("openvpn server certificate name %q does not start with verify-x509-name %q", cn, c.VerifyX509Name)
			}
		default:
			want, _ := parseOpenVPNSubject(c.VerifyX509Name)
			if got := subjectAttributes(leaf.Subject); !equalStrings(got, want) {
				return fmt.Errorf("openvpn server certificate subject %q does not match verify-x509-name %q", strings.Join(got, ", "), c.VerifyX509Name)
			}
		}
	}
	if c.VerifyServerName {
		if err := leaf.VerifyHostname(c.RemoteHost); err != nil {
			return fmt.Errorf("openvpn server certificate is not valid for %s: %w", c.RemoteHost, err)
		}
	}
	return nil
}

// ChecksServerIdentity reports whether anything beyond the CA chain and the
// server EKU is checked.
func (c *ClientConfig) ChecksServerIdentity() bool {
	return c.VerifyX509Name != "" || c.VerifyServerName
}

var subjectShortNames = map[string]string{
	"2.5.4.3":              "CN",
	"2.5.4.6":              "C",
	"2.5.4.7":              "L",
	"2.5.4.8":              "ST",
	"2.5.4.10":             "O",
	"2.5.4.11":             "OU",
	"2.5.4.5":              "serialNumber",
	"2.5.4.9":              "street",
	"2.5.4.17":             "postalCode",
	"1.2.840.113549.1.9.1": "emailAddress",
}

func attributeName(oid asn1.ObjectIdentifier) string {
	if name, ok := subjectShortNames[oid.String()]; ok {
		return name
	}
	return oid.String()
}

// subjectAttributes returns the subject as sorted "TYPE=value" strings.
func subjectAttributes(name pkix.Name) []string {
	attrs := make([]string, 0, len(name.Names))
	for _, atv := range name.Names {
		attrs = append(attrs, attributeName(atv.Type)+"="+fmt.Sprint(atv.Value))
	}
	sort.Strings(attrs)
	return attrs
}

// parseOpenVPNSubject parses an OpenVPN subject such as
// "C=KG, ST=NA, L=Bishkek, CN=Server-1" into sorted "TYPE=value" strings.
func parseOpenVPNSubject(subject string) ([]string, error) {
	var attrs []string
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		key, value, ok := strings.Cut(part, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || key == "" {
			return nil, fmt.Errorf("subject %q is not a list of TYPE=value", subject)
		}
		for oid, short := range subjectShortNames {
			if strings.EqualFold(key, short) || key == oid {
				key = short
				break
			}
		}
		attrs = append(attrs, key+"="+value)
	}
	sort.Strings(attrs)
	return attrs, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
