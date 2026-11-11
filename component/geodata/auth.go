package geodata

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
)

type AssetType string

const (
	AssetGeoIP   AssetType = "geoip"
	AssetMMDB    AssetType = "mmdb"
	AssetASN     AssetType = "asn"
	AssetGeoSite AssetType = "geosite"
)

var ErrAssetPinMismatch = errors.New("remote geodata SHA-256 mismatch")

// VerificationPolicy holds the optional per-type SHA-256 pins. An empty pin
// accepts the database as is: the publishers sign none of them.
type VerificationPolicy struct {
	GeoIP, MMDB, ASN, GeoSite string
}

var verificationPolicy atomic.Pointer[VerificationPolicy]

func SetVerificationPolicy(policy VerificationPolicy) {
	policy.GeoIP = strings.ToLower(strings.TrimSpace(policy.GeoIP))
	policy.MMDB = strings.ToLower(strings.TrimSpace(policy.MMDB))
	policy.ASN = strings.ToLower(strings.TrimSpace(policy.ASN))
	policy.GeoSite = strings.ToLower(strings.TrimSpace(policy.GeoSite))
	verificationPolicy.Store(&policy)
}

func CurrentVerificationPolicy() VerificationPolicy {
	if policy := verificationPolicy.Load(); policy != nil {
		return *policy
	}
	return VerificationPolicy{}
}

func (p VerificationPolicy) pin(asset AssetType) string {
	switch asset {
	case AssetGeoIP:
		return p.GeoIP
	case AssetMMDB:
		return p.MMDB
	case AssetASN:
		return p.ASN
	case AssetGeoSite:
		return p.GeoSite
	default:
		return ""
	}
}

func VerifyRemoteAsset(asset AssetType, data []byte) error {
	return VerifyRemoteDigest(asset, sha256.Sum256(data))
}

func VerifyRemoteDigest(asset AssetType, digest [sha256.Size]byte) error {
	policy := CurrentVerificationPolicy()
	pin := policy.pin(asset)
	if pin == "" {
		return nil
	}
	want, err := hex.DecodeString(pin)
	if err != nil || len(want) != sha256.Size {
		return fmt.Errorf("invalid configured SHA-256 pin for %s", asset)
	}
	if !equalDigest(digest[:], want) {
		return fmt.Errorf("%w: %s", ErrAssetPinMismatch, asset)
	}
	return nil
}

func equalDigest(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var diff byte
	for i := range left {
		diff |= left[i] ^ right[i]
	}
	return diff == 0
}
