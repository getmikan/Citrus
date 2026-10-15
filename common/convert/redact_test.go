package convert_test

import (
	"strings"
	"testing"
	"time"

	. "github.com/metacubex/mihomo/common/convert"
	"github.com/metacubex/mihomo/log"
)

func TestBadVlessLinkIsNotLoggedWithCredentials(t *testing.T) {
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)

	// No port: handleVShareLink fails after the link was parsed.
	link := "vless://11111111-2222-3333-4444-555555555555@example.com?security=reality&pbk=SECRETPUBLICKEY&sid=abcd#bad-node"
	go func() { _, _ = ConvertsV2Ray([]byte(link)) }()

	// Other code in the process may log at the same time, so skip lines
	// until the one about this link, but check every line for the secrets.
	timeout := time.After(5 * time.Second)
	for {
		select {
		case event := <-sub:
			for _, secret := range []string{"11111111-2222", "SECRETPUBLICKEY", "sid=abcd"} {
				if strings.Contains(event.Payload, secret) {
					t.Fatalf("log line leaks %q: %s", secret, event.Payload)
				}
			}
			if strings.Contains(event.Payload, "example.com") && strings.Contains(event.Payload, "bad-node") {
				return
			}
		case <-timeout:
			t.Fatal("no log line naming the server and the node")
		}
	}
}
