package reality

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestInvalidMLDSASeedErrorDoesNotDiscloseKey(t *testing.T) {
	for _, seed := range []string{
		"private-seed-with-invalid-encoding!",
		base64.RawURLEncoding.EncodeToString([]byte("private-seed-wrong-length")),
		base64.URLEncoding.EncodeToString([]byte("private-seed-padding-must-not-be-logged")),
	} {
		config := testConfig()
		config.Mldsa65Seed = seed
		_, err := config.Build(nil)
		if err == nil {
			t.Fatal("invalid seed accepted")
		}
		if strings.Contains(err.Error(), seed) {
			t.Fatal("error discloses secret seed")
		}
		if !strings.Contains(err.Error(), "mldsa65-seed") {
			t.Fatal("error does not identify the invalid option")
		}
	}
}
