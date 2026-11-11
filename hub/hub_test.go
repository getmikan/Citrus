package hub

import (
	"testing"

	"github.com/metacubex/mihomo/config"
)

func TestControllerReloaderAppliesOverrides(t *testing.T) {
	parse := func() *config.Config {
		cfg, err := config.Parse([]byte("external-controller: 0.0.0.0:9090\n"))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	// No secret in the file or on the command line: refused before anything
	// is applied.
	if _, err := controllerReloader(nil)(parse()); err == nil {
		t.Error("controller on all interfaces without a secret accepted")
	}

	// A secret survives the reload, but it is not a substitute for transport
	// confidentiality on remote plaintext HTTP.
	cfg := parse()
	if _, err := controllerReloader([]Option{WithSecret("s")})(cfg); err == nil {
		t.Error("remote plaintext controller with a secret was accepted without explicit opt-in")
	}
	if cfg.Controller.Secret != "s" {
		t.Errorf("secret after reload = %q, want the override", cfg.Controller.Secret)
	}

	if _, err := controllerReloader([]Option{WithExternalControllerAllowInsecure(true)})(parse()); err != nil {
		t.Errorf("with the allow-insecure override: %v", err)
	}
	if _, err := controllerReloader([]Option{WithSecret("s"), WithExternalControllerAllowInsecure(true)})(parse()); err != nil {
		t.Errorf("with secret and explicit plaintext opt-in: %v", err)
	}
}

func TestLegacyWebSocketTokenConfigIsExplicit(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		value := "false"
		if enabled {
			value = "true"
		}
		cfg, err := config.Parse([]byte("secret: test-secret\nexternal-controller-allow-legacy-websocket-token: " + value + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Controller.AllowLegacyWebSocketToken != enabled || routeConfig(cfg).AllowLegacyWebSocketToken != enabled {
			t.Fatal("legacy policy was lost while building controller config")
		}
	}
	cfg, err := config.Parse([]byte("secret: test-secret\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Controller.AllowLegacyWebSocketToken {
		t.Fatal("legacy URL secret was enabled by default")
	}
	WithExternalControllerAllowLegacyWebSocketToken(true)(cfg)
	if !routeConfig(cfg).AllowLegacyWebSocketToken {
		t.Fatal("legacy override ignored")
	}
}
