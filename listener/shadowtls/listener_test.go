package shadowtls

import (
	"strings"
	"testing"
	"time"

	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A ShadowTLS user with an empty password needs none to log in, so its user
// name is anyone's to take. The configuration still loads, with a warning.
func TestNewWarnsOfEmptyPassword(t *testing.T) {
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)

	_, err := New(LC.ShadowTLS{
		Enable:  true,
		Version: 3,
		Users: []LC.ShadowTLSUser{
			{Name: "has-secret", Password: "secret"},
			{Name: "no-secret"},
		},
		Handshake: LC.ShadowTLSHandshakeOptions{Dest: "example.com:443"},
	}, nil)
	require.NoError(t, err, "the listener still loads")

	deadline := time.After(2 * time.Second)
	for {
		select {
		case event := <-sub:
			if event.LogLevel != log.WARNING || !strings.Contains(event.Payload, "shadow-tls") {
				continue
			}
			assert.NotContains(t, event.Payload, `"has-secret"`, "a user with a password is warned of")
			if strings.Contains(event.Payload, `"no-secret"`) {
				assert.Contains(t, event.Payload, "empty secret")
				return
			}
		case <-deadline:
			t.Fatal("the empty password is not warned of")
		}
	}
}
