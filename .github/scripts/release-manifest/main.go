package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const domain = "CITRUS-UPDATE-MANIFEST-V1\n"

type artifact struct {
	Name   string `json:"name"`
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type manifest struct {
	Schema    int        `json:"schema"`
	Channel   string     `json:"channel"`
	Sequence  uint64     `json:"sequence"`
	Version   string     `json:"version"`
	Commit    string     `json:"commit"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	Artifacts []artifact `json:"artifacts"`
}
type signature struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}
type envelope struct {
	Schema     int         `json:"schema"`
	Signatures []signature `json:"signatures"`
}

func main() {
	dir := flag.String("dir", "bin", "artifact directory")
	channel := flag.String("channel", "", "release channel")
	version := flag.String("version", "", "release version")
	commit := flag.String("commit", "", "source commit")
	sequenceText := flag.String("sequence", "", "monotonic build sequence")
	expires := flag.Duration("expires", 30*24*time.Hour, "manifest validity")
	flag.Parse()
	sequence, err := strconv.ParseUint(*sequenceText, 10, 64)
	if err != nil || sequence == 0 || *channel == "" || *version == "" || *commit == "" {
		fatal("invalid channel/version/commit/sequence")
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		fatal(err.Error())
	}
	var artifacts []artifact
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".gz") && !strings.HasSuffix(name, ".zip")) || !strings.HasPrefix(name, "citrus-") || !strings.Contains(name, "-"+*version) {
			continue
		}
		base := strings.TrimSuffix(strings.TrimSuffix(name, ".gz"), ".zip")
		base = strings.TrimSuffix(base, "-"+*version)
		parts := strings.Split(base, "-")
		if len(parts) < 3 {
			fatal("cannot identify platform for " + name)
		}
		path := filepath.Join(*dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			fatal(err.Error())
		}
		info, _ := entry.Info()
		sum := sha256.Sum256(data)
		artifacts = append(artifacts, artifact{Name: name, GOOS: parts[1], GOARCH: parts[2], Size: info.Size(), SHA256: hex.EncodeToString(sum[:])})
	}
	if len(artifacts) == 0 {
		fatal("no core update artifacts")
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Name < artifacts[j].Name })
	now := time.Now().UTC().Truncate(time.Second)
	m := manifest{Schema: 1, Channel: *channel, Sequence: sequence, Version: *version, Commit: *commit, IssuedAt: now, ExpiresAt: now.Add(*expires), Artifacts: artifacts}
	manifestBytes, err := json.Marshal(m)
	if err != nil {
		fatal(err.Error())
	}
	message := append([]byte(domain), manifestBytes...)
	var signatures []signature
	for _, key := range []struct{ id, env string }{{"2026-primary", "CITRUS_UPDATE_PRIMARY_PRIVATE_KEY"}, {"2026-recovery", "CITRUS_UPDATE_RECOVERY_PRIVATE_KEY"}} {
		encoded := os.Getenv(key.env)
		privateKey, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(privateKey) != ed25519.PrivateKeySize {
			fatal(key.env + " is missing or invalid")
		}
		sig := ed25519.Sign(ed25519.PrivateKey(privateKey), message)
		signatures = append(signatures, signature{KeyID: key.id, Signature: base64.StdEncoding.EncodeToString(sig)})
	}
	envelopeBytes, _ := json.Marshal(envelope{Schema: 1, Signatures: signatures})
	if err := os.WriteFile(filepath.Join(*dir, "update-manifest.json"), manifestBytes, 0o644); err != nil {
		fatal(err.Error())
	}
	if err := os.WriteFile(filepath.Join(*dir, "update-manifest.sig.json"), envelopeBytes, 0o644); err != nil {
		fatal(err.Error())
	}
}

func fatal(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
