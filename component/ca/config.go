package ca

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/common/once"
	"github.com/metacubex/mihomo/ntp"

	"github.com/metacubex/tls"
)

var globalCertPool *x509.CertPool
var mutex sync.RWMutex
var errNotMatch = errors.New("certificate fingerprints do not match")

// _CaCertificates is the Mozilla root bundle as extracted by curl (https://curl.se/docs/caextract.html),
// committed to the repository and refreshed with update-ca-bundle.sh. The header of the file records
// the date of the Mozilla data it was built from.
//
//go:embed ca-certificates.crt
var _CaCertificates []byte

// bundlePEM is what the bundled pool is built from, a variable so tests can swap it.
var bundlePEM = _CaCertificates

// DisableEmbedCa and DisableSystemCa narrow the default RootsBoth source.
var DisableEmbedCa, _ = strconv.ParseBool(os.Getenv("DISABLE_EMBED_CA"))
var DisableSystemCa, _ = strconv.ParseBool(os.Getenv("DISABLE_SYSTEM_CA"))

// RootSource selects the pools behind the core's own TLS verification.
type RootSource uint8

const (
	RootsBoth   RootSource = iota // the system pool plus the bundled Mozilla roots, the default
	RootsBundle                   // only the bundled Mozilla roots, CAs installed on the device are ignored
	RootsSystem                   // only the system pool
)

func (s RootSource) String() string {
	switch s {
	case RootsBundle:
		return "bundle"
	case RootsSystem:
		return "system"
	default:
		return "both"
	}
}

// ParseRootSource parses the tls.ca-roots option, "" is the default RootsBoth.
func ParseRootSource(s string) (RootSource, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "both":
		return RootsBoth, nil
	case "bundle":
		return RootsBundle, nil
	case "system":
		return RootsSystem, nil
	}
	return RootsBoth, fmt.Errorf("unknown ca-roots %q, expected both, bundle or system", s)
}

// RootPolicy is the root CA policy of the core's TLS clients, the zero value is the default.
type RootPolicy struct {
	Source RootSource
	// DisableDenylist trusts the denylisted CAs again when the system pool or the bundle has them.
	DisableDenylist bool
}

var rootPolicy RootPolicy

// customSPKI holds the SubjectPublicKeyInfo hashes of the certificates added by AddCertificate,
// chains anchored at them are exempt from the denylist. It is replaced, never modified in place.
var customSPKI map[[sha256.Size]byte]struct{}

// SetRootPolicy sets the policy the next ResetCertificate builds the pool with.
func SetRootPolicy(policy RootPolicy) {
	mutex.Lock()
	defer mutex.Unlock()
	rootPolicy = policy
}

func AddCertificate(certificate string) error {
	mutex.Lock()
	defer mutex.Unlock()

	certs, err := decodeCertificate(certificate)
	if err != nil {
		return err
	}
	if globalCertPool == nil {
		initializeCertPool()
	}
	custom := make(map[[sha256.Size]byte]struct{}, len(customSPKI)+len(certs))
	for hash := range customSPKI {
		custom[hash] = struct{}{}
	}
	for _, cert := range certs {
		globalCertPool.AddCert(cert)
		custom[spkiHash(cert)] = struct{}{}
	}
	customSPKI = custom
	return nil
}

// decodeCertificate returns the certificates of a tls.custom-certifactes entry, PEM or a single DER.
func decodeCertificate(certificate string) ([]*x509.Certificate, error) {
	if certificate == "" {
		return nil, fmt.Errorf("certificate is empty")
	}
	certs := parseCertificates([]byte(certificate))
	if len(certs) == 0 {
		cert, err := x509.ParseCertificate([]byte(certificate))
		if err != nil {
			return nil, fmt.Errorf("add certificate failed")
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// Roots is a root pool with the policy and the tls.custom-certifactes it was built from. Most proxies
// keep the pool [GetTLSConfig] or [GetCertPool] gave them when they were built, so a config builds its
// Roots and installs them with [SwapRoots] before its proxies are parsed.
type Roots struct {
	pool   *x509.CertPool
	policy RootPolicy
	custom map[[sha256.Size]byte]struct{}
}

// NewRoots builds the pool of policy with certificates on top without installing it. The certificates
// that cannot be decoded are left out and returned in errs.
func NewRoots(policy RootPolicy, certificates []string) (r *Roots, errs []error) {
	r = &Roots{pool: buildPool(policy), policy: policy}
	for _, certificate := range certificates {
		certs, err := decodeCertificate(certificate)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s\nadd error: %w", certificate, err))
			continue
		}
		if r.custom == nil {
			r.custom = make(map[[sha256.Size]byte]struct{}, len(certs))
		}
		for _, cert := range certs {
			r.pool.AddCert(cert)
			r.custom[spkiHash(cert)] = struct{}{}
		}
	}
	return
}

// SwapRoots installs r and returns the roots it replaced, so they can be put back. nil is the default
// policy without custom certificates.
func SwapRoots(r *Roots) (prev *Roots) {
	mutex.Lock()
	defer mutex.Unlock()
	prev = &Roots{pool: globalCertPool, policy: rootPolicy, custom: customSPKI}
	if r == nil {
		r = &Roots{}
	}
	// a nil pool is built by the next GetCertPool, with no custom certificates
	globalCertPool, rootPolicy, customSPKI = r.pool, r.policy, r.custom
	return prev
}

// parseCertificates returns the certificates of the PEM blocks in data like AppendCertsFromPEM,
// skipping the blocks it cannot parse.
func parseCertificates(data []byte) (certs []*x509.Certificate) {
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, cert)
		}
	}
	return
}

// appendBundle adds the bundled roots to pool, leaving out the denylisted ones when denylist is set,
// and returns how many it added.
func appendBundle(pool *x509.CertPool, denylist bool) (n int) {
	for _, cert := range parseCertificates(bundlePEM) {
		if denylist && denylistedName(cert) != "" {
			continue
		}
		pool.AddCert(cert)
		n++
	}
	return
}

func initializeCertPool() {
	customSPKI = nil
	globalCertPool = buildPool(rootPolicy)
}

func buildPool(policy RootPolicy) (pool *x509.CertPool) {
	useSystem, useBundle := true, true
	switch policy.Source {
	case RootsBundle:
		useSystem = false
	case RootsSystem:
		useBundle = false
	default:
		useSystem, useBundle = !DisableSystemCa, !DisableEmbedCa
	}

	var err error
	if useSystem {
		// The system pool cannot be filtered (on Windows and macOS it is the platform verifier),
		// CheckChains rejects its denylisted CAs after the verification instead.
		pool, err = x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
	} else {
		pool = x509.NewCertPool()
	}
	if useBundle {
		appendBundle(pool, !policy.DisableDenylist)
	}
	return pool
}

func ResetCertificate() {
	mutex.Lock()
	defer mutex.Unlock()
	initializeCertPool()
}

func GetCertPool() *x509.CertPool {
	mutex.Lock()
	defer mutex.Unlock()
	if globalCertPool == nil {
		initializeCertPool()
	}
	return globalCertPool
}

type Option struct {
	TLSConfig      *tls.Config
	Fingerprint    string
	NameCertVerify string
	ZeroTrust      bool
	Certificate    string
	PrivateKey     string
}

func GetTLSConfig(opt Option) (tlsConfig *tls.Config, err error) {
	tlsConfig = opt.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	tlsConfig.Time = ntp.Now

	if opt.ZeroTrust {
		tlsConfig.RootCAs = zeroTrustCertPool()
	} else {
		tlsConfig.RootCAs = GetCertPool()
	}

	if len(opt.Fingerprint) > 0 {
		// A pinned certificate is trusted explicitly, the denylist does not apply to it.
		verifier, err := NewFingerprintNameVerifier(opt.Fingerprint, opt.NameCertVerify, tlsConfig.Time)
		if err != nil {
			return nil, err
		}
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			// [ConnectionState.ServerName] can return the actual ServerName needed for verification,
			// avoiding inconsistencies caused by [tlsConfig.ServerName] being modified after the [NewFingerprintVerifier] call.
			// https://github.com/golang/go/issues/36736#issuecomment-587925536
			// The names of opt.NameCertVerify are used instead of it when set.
			return verifier(state.PeerCertificates, state.ServerName)
		}
		tlsConfig.InsecureSkipVerify = true
	} else if opt.NameCertVerify != "" {
		verifier := NewNameCertVerifier(opt.NameCertVerify, tlsConfig.RootCAs, tlsConfig.Time)
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			return verifier(state.PeerCertificates)
		}
		tlsConfig.InsecureSkipVerify = true
	} else {
		// With skip-cert-verify there are no VerifiedChains, so CheckChains lets it through.
		next := tlsConfig.VerifyConnection
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if err := CheckChains(state.VerifiedChains); err != nil {
				return err
			}
			if next != nil {
				return next(state)
			}
			return nil
		}
	}

	if len(opt.Certificate) > 0 || len(opt.PrivateKey) > 0 {
		certLoader, err := NewTLSKeyPairLoader(opt.Certificate, opt.PrivateKey)
		if err != nil {
			return nil, err
		}
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return certLoader()
		}
	}
	return tlsConfig, nil
}

// zeroTrustCertPool is the bundle alone, always without the denylisted CAs.
var zeroTrustCertPool = once.OnceValue(func() *x509.CertPool {
	zeroTrustCertPool := x509.NewCertPool()
	if appendBundle(zeroTrustCertPool, true) > 0 { // always using embed cert first
		return zeroTrustCertPool
	}
	return nil // fallback to system pool
})
