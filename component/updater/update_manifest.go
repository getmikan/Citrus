package updater

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

const (
	updateManifestFileName  = "update-manifest.json"
	updateSignatureFileName = "update-manifest.sig.json"
	updateManifestDomain    = "CITRUS-UPDATE-MANIFEST-V1\n"
	maxUpdateManifestSize   = 2 << 20
	maxUpdateSignatureSize  = 64 << 10
)

type updateManifest struct {
	Schema    int              `json:"schema"`
	Channel   string           `json:"channel"`
	Sequence  uint64           `json:"sequence"`
	Version   string           `json:"version"`
	Commit    string           `json:"commit"`
	IssuedAt  time.Time        `json:"issued_at"`
	ExpiresAt time.Time        `json:"expires_at"`
	Artifacts []updateArtifact `json:"artifacts"`
}

type updateArtifact struct {
	Name   string `json:"name"`
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type updateSignatureEnvelope struct {
	Schema     int               `json:"schema"`
	Signatures []updateSignature `json:"signatures"`
}

type updateSignature struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

var trustedUpdateKeys = map[string]string{
	"2026-primary":  "6NDO5v4Z014bvqVboaENGkKmjNOL4PMDpQCVUg7Lmnc=",
	"2026-recovery": "w9Ak+ICCUcgB0fdnO7J5/QyNfdl7iQKkOIuW1CDINs4=",
}

var revokedUpdateKeys = map[string]bool{}

func strictJSON(data []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func verifyManifestSignature(manifestBytes, signatureBytes []byte, keys map[string]string, revoked map[string]bool) error {
	var envelope updateSignatureEnvelope
	if err := strictJSON(signatureBytes, &envelope); err != nil {
		return fmt.Errorf("signature envelope: %w", err)
	}
	if envelope.Schema != 1 || len(envelope.Signatures) == 0 {
		return errors.New("signature envelope has unsupported schema or no signatures")
	}
	message := append([]byte(updateManifestDomain), manifestBytes...)
	for _, candidate := range envelope.Signatures {
		if revoked[candidate.KeyID] {
			continue
		}
		encodedKey, ok := keys[candidate.KeyID]
		if !ok {
			continue
		}
		key, keyErr := base64.StdEncoding.DecodeString(encodedKey)
		signature, sigErr := base64.StdEncoding.DecodeString(candidate.Signature)
		if keyErr == nil && sigErr == nil && len(key) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(key), message, signature) {
			return nil
		}
	}
	return errors.New("manifest is not signed by a trusted non-revoked update key")
}

func buildSequence() uint64 {
	value, _ := strconv.ParseUint(C.BuildSequence, 10, 64)
	return value
}

func verifyUpdateManifest(manifestBytes, signatureBytes []byte, channel, coreBaseName string, minimumSequence uint64, now time.Time) (updateManifest, updateArtifact, error) {
	if err := verifyManifestSignature(manifestBytes, signatureBytes, trustedUpdateKeys, revokedUpdateKeys); err != nil {
		return updateManifest{}, updateArtifact{}, err
	}
	var manifest updateManifest
	if err := strictJSON(manifestBytes, &manifest); err != nil {
		return updateManifest{}, updateArtifact{}, fmt.Errorf("manifest: %w", err)
	}
	if manifest.Schema != 1 || manifest.Channel != channel || !validVersion(manifest.Version) {
		return updateManifest{}, updateArtifact{}, errors.New("manifest schema, channel or version is invalid")
	}
	commit, err := hex.DecodeString(manifest.Commit)
	if err != nil || len(commit) != sha256.Size-12 {
		return updateManifest{}, updateArtifact{}, errors.New("manifest commit is not a full Git SHA-1")
	}
	if manifest.IssuedAt.After(now.Add(5*time.Minute)) || !manifest.ExpiresAt.After(now) || manifest.ExpiresAt.Sub(manifest.IssuedAt) > 120*24*time.Hour {
		return updateManifest{}, updateArtifact{}, errors.New("manifest validity period is invalid or expired")
	}
	if manifest.Sequence <= minimumSequence || manifest.Sequence <= buildSequence() {
		return updateManifest{}, updateArtifact{}, fmt.Errorf("manifest sequence %d is not newer than the trusted state", manifest.Sequence)
	}
	packageName := coreBaseName + "-" + manifest.Version
	if runtime.GOOS == "windows" {
		packageName += ".zip"
	} else {
		packageName += ".gz"
	}
	seen := make(map[string]struct{}, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		if _, exists := seen[artifact.Name]; exists {
			return updateManifest{}, updateArtifact{}, fmt.Errorf("duplicate manifest artifact %q", artifact.Name)
		}
		seen[artifact.Name] = struct{}{}
		if artifact.Name != packageName {
			continue
		}
		if artifact.GOOS != runtime.GOOS || artifact.GOARCH != runtime.GOARCH || artifact.Size <= 0 || artifact.Size > MaxPackageFileSize {
			return updateManifest{}, updateArtifact{}, errors.New("manifest artifact platform or size does not match this binary")
		}
		digest, err := hex.DecodeString(artifact.SHA256)
		if err != nil || len(digest) != sha256.Size {
			return updateManifest{}, updateArtifact{}, errors.New("manifest artifact SHA-256 is invalid")
		}
		return manifest, artifact, nil
	}
	return updateManifest{}, updateArtifact{}, fmt.Errorf("manifest has no artifact %q", packageName)
}
