package route

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/config"
	LC "github.com/metacubex/mihomo/listener/config"
)

func TestRedactGeneral(t *testing.T) {
	ss := LC.ShadowsocksServer{
		Enable:   true,
		Listen:   "0.0.0.0:8388",
		Password: "server-ipsk",
		Cipher:   "2022-blake3-aes-128-gcm",
		Users:    []LC.ShadowsocksUser{{Name: "alice", Password: "alice-upsk"}},
		ShadowTLS: LC.ShadowTLS{
			Enable:   true,
			Password: "stls-pass",
			Users:    []LC.ShadowTLSUser{{Name: "bob", Password: "bob-stls"}},
		},
	}
	users := map[string]string{"00000000-0000-0000-0000-000000000001": "tuic-pass"}
	tokens := []string{"tuic-token"}
	g := &config.General{Inbound: config.Inbound{
		TuicServer: LC.TuicServer{
			Enable:      true,
			Listen:      "0.0.0.0:443",
			Token:       tokens,
			Users:       users,
			Certificate: "cert.pem",
			PrivateKey:  "-----BEGIN PRIVATE KEY-----\ninline\n-----END PRIVATE KEY-----",
			EchKey:      "ech-secret",
		},
		ShadowSocksConfig: ss.String(),
	}}

	redactGeneral(g)

	out, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"server-ipsk", "alice-upsk", "stls-pass", "bob-stls", "tuic-pass", "tuic-token", "inline", "ech-secret"} {
		if strings.Contains(string(out), secret) {
			t.Errorf("GET /configs still contains %q: %s", secret, out)
		}
	}
	for _, kept := range []string{"0.0.0.0:8388", "2022-blake3-aes-128-gcm", "alice", "00000000-0000-0000-0000-000000000001", "cert.pem"} {
		if !strings.Contains(string(out), kept) {
			t.Errorf("GET /configs lost %q: %s", kept, out)
		}
	}
	// The live configuration is not touched.
	if tokens[0] != "tuic-token" || users["00000000-0000-0000-0000-000000000001"] != "tuic-pass" {
		t.Error("redaction changed the running TUIC configuration")
	}

	if got := redactJSONString("not json"); got != redacted {
		t.Errorf("unparsable ss-config = %q, want it redacted", got)
	}
	if got := redactJSONString(""); got != "" {
		t.Errorf("empty ss-config = %q", got)
	}
}
