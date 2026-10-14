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

	// A secret given by -secret survives the reload.
	cfg := parse()
	if _, err := controllerReloader([]Option{WithSecret("s")})(cfg); err != nil {
		t.Errorf("with the -secret override: %v", err)
	}
	if cfg.Controller.Secret != "s" {
		t.Errorf("secret after reload = %q, want the override", cfg.Controller.Secret)
	}

	if _, err := controllerReloader([]Option{WithExternalControllerAllowInsecure(true)})(parse()); err != nil {
		t.Errorf("with the allow-insecure override: %v", err)
	}
}
