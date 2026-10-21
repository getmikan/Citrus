package updater

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"testing"
	"time"
)

func signedManifestFixture(t *testing.T, mutate func(*updateManifest)) ([]byte, []byte, string) {
	t.Helper()
	seed := sha256.Sum256([]byte("citrus update test key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	now := time.Now().UTC().Truncate(time.Second)
	coreBase := "citrus-test"
	name := coreBase + "-v1.2.3"
	if runtime.GOOS == "windows" {
		name += ".zip"
	} else {
		name += ".gz"
	}
	pkgDigest := sha256.Sum256([]byte("package"))
	manifest := updateManifest{
		Schema: 1, Channel: ReleaseChannel, Sequence: buildSequence() + 100,
		Version: "v1.2.3", Commit: "0123456789abcdef0123456789abcdef01234567",
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(24 * time.Hour),
		Artifacts: []updateArtifact{{Name: name, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Size: 7, SHA256: fmt.Sprintf("%x", pkgDigest)}},
	}
	if mutate != nil {
		mutate(&manifest)
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, append([]byte(updateManifestDomain), manifestBytes...))
	envelopeBytes, _ := json.Marshal(updateSignatureEnvelope{Schema: 1, Signatures: []updateSignature{{KeyID: "test", Signature: base64.StdEncoding.EncodeToString(signature)}}})
	oldKeys, oldRevoked := trustedUpdateKeys, revokedUpdateKeys
	trustedUpdateKeys = map[string]string{"test": base64.StdEncoding.EncodeToString(publicKey)}
	revokedUpdateKeys = map[string]bool{}
	t.Cleanup(func() { trustedUpdateKeys, revokedUpdateKeys = oldKeys, oldRevoked })
	return manifestBytes, envelopeBytes, coreBase
}

func TestVerifySignedUpdateManifest(t *testing.T) {
	manifest, signatures, coreBase := signedManifestFixture(t, nil)
	parsed, artifact, err := verifyUpdateManifest(manifest, signatures, ReleaseChannel, coreBase, 0, time.Now())
	if err != nil || parsed.Version != "v1.2.3" || artifact.Name == "" {
		t.Fatalf("valid manifest: parsed=%+v artifact=%+v err=%v", parsed, artifact, err)
	}

	tampered := append([]byte(nil), manifest...)
	tampered[len(tampered)-1] ^= 1
	if _, _, err := verifyUpdateManifest(tampered, signatures, ReleaseChannel, coreBase, 0, time.Now()); err == nil {
		t.Fatal("tampered manifest accepted")
	}
	revokedUpdateKeys["test"] = true
	if _, _, err := verifyUpdateManifest(manifest, signatures, ReleaseChannel, coreBase, 0, time.Now()); err == nil {
		t.Fatal("revoked key accepted")
	}
}

func TestUpdateManifestRejectsExpiryChannelAndRollback(t *testing.T) {
	manifest, signatures, coreBase := signedManifestFixture(t, nil)
	var parsed updateManifest
	_ = json.Unmarshal(manifest, &parsed)
	if _, _, err := verifyUpdateManifest(manifest, signatures, DevChannel, coreBase, 0, time.Now()); err == nil {
		t.Fatal("cross-channel manifest accepted")
	}
	if _, _, err := verifyUpdateManifest(manifest, signatures, ReleaseChannel, coreBase, parsed.Sequence, time.Now()); err == nil {
		t.Fatal("replayed manifest sequence accepted")
	}
	expired, expiredSig, expiredBase := signedManifestFixture(t, func(m *updateManifest) { m.ExpiresAt = time.Now().Add(-time.Minute) })
	if _, _, err := verifyUpdateManifest(expired, expiredSig, ReleaseChannel, expiredBase, 0, time.Now()); err == nil {
		t.Fatal("expired manifest accepted")
	}
}
