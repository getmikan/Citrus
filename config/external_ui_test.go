package config

import (
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
