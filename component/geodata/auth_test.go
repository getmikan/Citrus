package geodata

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyRemoteAsset(t *testing.T) {
	old := CurrentVerificationPolicy()
	t.Cleanup(func() { SetVerificationPolicy(old) })
	data := []byte("geo")
	pin := fmt.Sprintf("%x", sha256.Sum256(data))
	SetVerificationPolicy(VerificationPolicy{GeoIP: pin, MMDB: pin, ASN: pin, GeoSite: pin})
	for _, asset := range []AssetType{AssetGeoIP, AssetMMDB, AssetASN, AssetGeoSite} {
		if err := VerifyRemoteAsset(asset, data); err != nil {
			t.Errorf("%s correct pin: %v", asset, err)
		}
		if err := VerifyRemoteAsset(asset, []byte("tampered")); err == nil {
			t.Errorf("%s accepted wrong digest", asset)
		}
	}
	SetVerificationPolicy(VerificationPolicy{})
	if err := VerifyRemoteAsset(AssetGeoIP, data); err != nil {
		t.Fatalf("unpinned database rejected: %v", err)
	}
}

func TestExistingAssetMustMatchCurrentPin(t *testing.T) {
	old := CurrentVerificationPolicy()
	t.Cleanup(func() { SetVerificationPolicy(old) })
	data := []byte("existing")
	path := filepath.Join(t.TempDir(), "GeoIP.dat")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	SetVerificationPolicy(VerificationPolicy{GeoIP: fmt.Sprintf("%x", sha256.Sum256(data))})
	if err := verifyExistingAsset(AssetGeoIP, path); err != nil {
		t.Fatal(err)
	}
	SetVerificationPolicy(VerificationPolicy{GeoIP: fmt.Sprintf("%064x", 1)})
	if err := verifyExistingAsset(AssetGeoIP, path); err == nil {
		t.Fatal("legacy existing file bypassed the current pin")
	}
}
