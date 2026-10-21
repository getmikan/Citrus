package config

import (
	"os"
	"path/filepath"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestExternalUIRefusesCoreDirectories(t *testing.T) {
	home := C.Path.HomeDir()
	for _, tc := range []struct {
		ui, name string
		ok       bool
	}{
		{"", "", true},
		{"ui", "", true},
		{"ui", "zashboard", true},
		{"", "metacubexd", true},
		{".", "", false},
		{"./", "", false},
		{home, "", false},
		{filepath.Dir(home), "", false},
		{".", "ui", false}, // external-ui itself is served by /ui
	} {
		err := CheckExternalUI(tc.ui, tc.name)
		if (err == nil) != tc.ok {
			t.Errorf("CheckExternalUI(%q, %q) = %v, want ok=%v", tc.ui, tc.name, err, tc.ok)
		}
	}

	if _, err := parseController(&RawConfig{ExternalUI: "."}); err == nil {
		t.Error("a config with external-ui: . was accepted")
	}
}

func TestExternalUIRefusesSymlinkToCoreState(t *testing.T) {
	home := C.Path.HomeDir()
	if _, err := os.Stat(home); err != nil {
		t.Skipf("core home is unavailable: %v", err)
	}
	link := filepath.Join(t.TempDir(), "ui")
	if err := os.Symlink(home, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := CheckExternalUI(link, ""); err == nil {
		t.Fatal("external UI symlink to core home was accepted")
	}
}

func TestParseControllerRejectsConflictingDoHPath(t *testing.T) {
	for _, dohPath := range []string{"/", "/c", "/config", "/configs", "/configs/doh", "/up", "/dns%2Dquery", "/dns-query/../configs"} {
		if _, err := parseController(&RawConfig{ExternalDohServer: dohPath}); err == nil {
			t.Errorf("external-doh-server %q was accepted", dohPath)
		}
	}
	if _, err := parseController(&RawConfig{ExternalDohServer: "/dns-query"}); err != nil {
		t.Fatalf("normal DoH endpoint rejected: %v", err)
	}
}
