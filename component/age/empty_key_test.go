package age_test

import (
	"testing"

	"github.com/metacubex/mihomo/component/age"
)

// A proxy-provider without its own age-secret-key passes "" next to the
// global keys; the empty key must be skipped, not rejected.
func TestDecryptBytesSkipsEmptySecretKey(t *testing.T) {
	secretKey, publicKey, err := age.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := age.EncryptBytes([]byte("payload"), publicKey)
	if err != nil {
		t.Fatal(err)
	}

	age.SetGlobalSecretKeys(secretKey)
	t.Cleanup(func() { age.SetGlobalSecretKeys() })

	decrypted, err := age.DecryptBytes(encrypted, "")
	if err != nil {
		t.Fatalf("DecryptBytes with an empty key: %v", err)
	}
	if string(decrypted) != "payload" {
		t.Fatalf("got %q, want %q", decrypted, "payload")
	}
}
