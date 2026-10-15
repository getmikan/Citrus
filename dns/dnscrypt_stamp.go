package dns

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	D "github.com/miekg/dns"
)

// DNS stamp protocol identifiers, see https://dnscrypt.info/stamps-specifications
const (
	stampProtoPlain     = 0x00
	stampProtoDNSCrypt  = 0x01
	stampProtoDoH       = 0x02
	stampProtoDoT       = 0x03
	stampProtoDoQ       = 0x04
	stampProtoODoH      = 0x05
	stampProtoRelay     = 0x81
	stampProtoODoHRelay = 0x85

	dnsCryptStampScheme  = "sdns://"
	dnsCryptDefaultPort  = "443"
	dnsCryptProviderKeyN = ed25519.PublicKeySize
)

// dnsCryptStamp is a decoded DNSCrypt (protocol 0x01) sdns:// stamp.
type dnsCryptStamp struct {
	Props        uint64            // informal properties (DNSSEC, no logs, no filter)
	ServerAddr   string            // host:port of the resolver, the port defaults to 443
	ProviderPK   ed25519.PublicKey // signs the resolver certificates
	ProviderName string            // FQDN the certificates are requested for, e.g. 2.dnscrypt-cert.example.com.
}

// ValidateDNSCryptStamp reports whether s is a DNSCrypt sdns:// stamp the
// dnscrypt client can use. Config parsing calls it to fail fast.
func ValidateDNSCryptStamp(s string) error {
	_, err := parseDNSCryptStamp(s)
	return err
}

// parseDNSCryptStamp decodes an sdns:// stamp. Only DNSCrypt stamps are
// accepted: the other protocols already have a native nameserver scheme, and
// the error says which one to use.
func parseDNSCryptStamp(s string) (*dnsCryptStamp, error) {
	if !strings.HasPrefix(s, dnsCryptStampScheme) {
		return nil, errors.New("DNS stamp must start with sdns://")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s[len(dnsCryptStampScheme):], "="))
	if err != nil {
		return nil, fmt.Errorf("invalid DNS stamp encoding: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("empty DNS stamp")
	}
	switch raw[0] {
	case stampProtoDNSCrypt:
	case stampProtoPlain:
		return nil, errors.New("plain DNS stamps are not supported, use udp:// or tcp:// instead")
	case stampProtoDoH:
		return nil, errors.New("DNS-over-HTTPS stamps are not supported, use an https:// nameserver instead")
	case stampProtoDoT:
		return nil, errors.New("DNS-over-TLS stamps are not supported, use a tls:// nameserver instead")
	case stampProtoDoQ:
		return nil, errors.New("DNS-over-QUIC stamps are not supported, use a quic:// nameserver instead")
	case stampProtoODoH, stampProtoRelay, stampProtoODoHRelay:
		return nil, fmt.Errorf("DNS stamp protocol 0x%02x (relay/oblivious DoH) is not supported", raw[0])
	default:
		return nil, fmt.Errorf("unknown DNS stamp protocol 0x%02x", raw[0])
	}

	if len(raw) < 9 {
		return nil, errors.New("DNSCrypt stamp is too short")
	}
	stamp := &dnsCryptStamp{Props: binary.LittleEndian.Uint64(raw[1:9])}
	rest := raw[9:]

	var addr, pk, name []byte
	if addr, rest, err = readStampLP(rest); err != nil {
		return nil, fmt.Errorf("DNSCrypt stamp server address: %w", err)
	}
	if pk, rest, err = readStampLP(rest); err != nil {
		return nil, fmt.Errorf("DNSCrypt stamp provider key: %w", err)
	}
	if name, rest, err = readStampLP(rest); err != nil {
		return nil, fmt.Errorf("DNSCrypt stamp provider name: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("DNSCrypt stamp has trailing data")
	}

	if stamp.ServerAddr, err = normalizeStampAddr(string(addr)); err != nil {
		return nil, fmt.Errorf("DNSCrypt stamp server address: %w", err)
	}
	if len(pk) != dnsCryptProviderKeyN {
		return nil, fmt.Errorf("DNSCrypt stamp provider key must be %d bytes, got %d", dnsCryptProviderKeyN, len(pk))
	}
	stamp.ProviderPK = ed25519.PublicKey(pk)
	if len(name) == 0 {
		return nil, errors.New("DNSCrypt stamp provider name is empty")
	}
	stamp.ProviderName = D.Fqdn(string(name))
	if _, ok := D.IsDomainName(stamp.ProviderName); !ok {
		return nil, fmt.Errorf("DNSCrypt stamp provider name %q is not a domain name", name)
	}
	return stamp, nil
}

func readStampLP(b []byte) (value, rest []byte, err error) {
	if len(b) == 0 {
		return nil, nil, errors.New("missing")
	}
	n := int(b[0])
	if len(b) < 1+n {
		return nil, nil, errors.New("truncated")
	}
	return b[1 : 1+n], b[1+n:], nil
}

// normalizeStampAddr turns the stamp address (IP, [IPv6], optionally with a
// port) into host:port.
func normalizeStampAddr(addr string) (string, error) {
	if addr == "" {
		return "", errors.New("empty")
	}
	if ip, err := netip.ParseAddr(addr); err == nil {
		return net.JoinHostPort(ip.String(), dnsCryptDefaultPort), nil
	}
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		return normalizeStampAddr(addr[1 : len(addr)-1])
	}
	if !strings.Contains(addr, ":") { // host name without a port
		return net.JoinHostPort(addr, dnsCryptDefaultPort), nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if host == "" || port == "" {
		return "", fmt.Errorf("invalid address %q", addr)
	}
	return net.JoinHostPort(host, port), nil
}
