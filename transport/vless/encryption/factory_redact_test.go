package encryption

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestFactoryErrorsDoNotLeakKeys(t *testing.T) {
	privateKey := base64.RawURLEncoding.EncodeToString(make([]byte, X25519PrivateKeySize))
	seed := base64.RawURLEncoding.EncodeToString(make([]byte, MLKEM768SeedLength))
	badKey := base64.RawURLEncoding.EncodeToString(make([]byte, 33)) // wrong length

	for _, value := range []string{
		"mlkem768x25519plus.bogus.600s." + privateKey + "." + seed,
		"mlkem768x25519plus.native.xs." + privateKey + "." + seed,
		"mlkem768x25519plus.native.600-xs." + privateKey + "." + seed,
		"mlkem768x25519plus.native.600s." + privateKey + "." + badKey,
		"mlkem768x25519plus.native.600s." + privateKey + ".!!!!!!!!!!!!!!!!!!!!!!!!",
		"mlkem768x25519plus.native." + privateKey,
	} {
		_, err := NewServer(value)
		if err == nil {
			t.Fatalf("accepted %q", value)
		}
		if strings.Contains(err.Error(), privateKey) || strings.Contains(err.Error(), seed) {
			t.Fatalf("error leaks key material: %v", err)
		}
	}

	// The client side names the failing component as well.
	_, err := NewClient("mlkem768x25519plus.native.2rtt." + privateKey)
	if err == nil || strings.Contains(err.Error(), privateKey) || !strings.Contains(err.Error(), "component 3") {
		t.Fatalf("client error: %v", err)
	}
}
