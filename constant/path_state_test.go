package constant

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHoldsCoreState(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home", "citrus")
	extra := filepath.Join(base, "share", "ui-root")
	p := &path{homeDir: home, configFile: "config.yaml", safePaths: []string{extra}}

	for dir, want := range map[string]bool{
		".":                                   true, // the home itself
		home:                                  true,
		home + string(filepath.Separator):     true,
		filepath.Join(home, ".."):             true, // an ancestor of the home
		base:                                  true,
		extra:                                 true, // a SAFE_PATHS root
		filepath.Join(base, "share"):          true,
		"ui":                                  false,
		filepath.Join(home, "ui"):             false,
		filepath.Join(home, "ui", "zash"):     false,
		filepath.Join(extra, "metacubexd"):    false,
		filepath.Join(base, "elsewhere", "x"): false,
	} {
		if got := p.HoldsCoreState(dir); got != want {
			t.Errorf("HoldsCoreState(%q) = %v, want %v", dir, got, want)
		}
	}

	// The directory of a config file outside the home counts too.
	etc := filepath.Join(base, "etc", "citrus")
	p.configFile = filepath.Join(etc, "config.yaml")
	if !p.HoldsCoreState(etc) || !p.HoldsCoreState(filepath.Join(base, "etc")) {
		t.Error("the config directory or its parent is not protected")
	}
	if p.HoldsCoreState(filepath.Join(etc, "ui")) {
		t.Error("a subdirectory of the config directory is protected")
	}

	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	uiLink := filepath.Join(base, "ui-link")
	if err := os.Symlink(home, uiLink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if !p.HoldsCoreState(uiLink) {
		t.Error("a symlink to the home directory was not protected")
	}
}
