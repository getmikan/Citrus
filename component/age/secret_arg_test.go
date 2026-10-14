package age

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretKeyArg(t *testing.T) {
	secretKey, _, err := GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(file, []byte("# created: now\n"+secretKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := secretKeyArg("@" + file)
	if err != nil {
		t.Fatal(err)
	}
	if err := VeritySecretKeys(got); err != nil {
		t.Errorf("key read from the file does not parse: %v", err)
	}
	if got, _ := secretKeyArg(secretKey); got != secretKey {
		t.Error("a literal key is not passed through")
	}
	if _, err := secretKeyArg("@" + filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing key file is not an error")
	}
}
