package updater

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallKeepsCurrentOnFailure(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "citrus")
	if err := os.WriteFile(current, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := &CoreUpdater{}
	if err := u.install(filepath.Join(dir, "missing"), current); err == nil {
		t.Fatal("install of a missing binary succeeded")
	}
	if got, err := os.ReadFile(current); err != nil || string(got) != "old" {
		t.Fatalf("failed install changed the current binary: %q, %v", got, err)
	}
	if _, err := os.Stat(current + ".new"); !os.IsNotExist(err) {
		t.Fatalf("failed install left its temp file: %v", err)
	}

	update := filepath.Join(dir, "update")
	if err := os.WriteFile(update, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := u.install(update, current); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(current); string(got) != "new" {
		t.Fatalf("install wrote %q", got)
	}
}

func TestRestorePutsBackupBack(t *testing.T) {
	u := &CoreUpdater{}
	// The current binary missing (the Windows backup renamed it away) and
	// present (the new binary was installed) must both restore.
	for _, existing := range []bool{false, true} {
		dir := t.TempDir()
		current := filepath.Join(dir, "citrus")
		backup := filepath.Join(dir, "backup")
		if err := os.WriteFile(backup, []byte("old"), 0o755); err != nil {
			t.Fatal(err)
		}
		if existing {
			if err := os.WriteFile(current, []byte("new"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := u.restore(backup, current); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(current); string(got) != "old" {
			t.Fatalf("existing=%v: restored %q", existing, got)
		}
	}
}

func TestCoreBaseName(t *testing.T) {
	name := DefaultCoreUpdater.CoreBaseName()
	if !strings.HasPrefix(name, "citrus-") {
		t.Fatalf("release asset must use the Citrus prefix: %q", name)
	}
}

func TestCoreChannelURLs(t *testing.T) {
	tests := []struct {
		name    string
		channel string
		version string
		path    string
	}{
		{"main", "main", "v1.0.0", "/getmikan/Citrus/releases/download/Prerelease-main/"},
		{"legacy alpha channel", "alpha", "v1.0.0", "/getmikan/Citrus/releases/download/Prerelease-main/"},
		{"case insensitive alpha channel", "ALPHA", "v1.0.0", "/getmikan/Citrus/releases/download/Prerelease-main/"},
		{"explicit auto channel", "auto", "main-abc123", "/getmikan/Citrus/releases/download/Prerelease-main/"},
		{"main build", "", "main-abc123", "/getmikan/Citrus/releases/download/Prerelease-main/"},
		{"unversioned main build", "", "main", "/getmikan/Citrus/releases/download/Prerelease-main/"},
		{"release build", "", "v1.0.0", "/getmikan/Citrus/releases/latest/download/"},
		{"explicit release", "release", "main-abc123", "/getmikan/Citrus/releases/latest/download/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, version, err := coreChannelURLs(tt.channel, tt.version)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range []string{base, version} {
				parsed, err := url.Parse(value)
				if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" {
					t.Fatalf("invalid trusted update URL %q: %v", value, err)
				}
			}
			if base != "https://github.com"+tt.path || version != base+updateManifestFileName {
				t.Fatalf("wrong channel URLs: %q, %q", base, version)
			}
		})
	}
}

func TestCoreChannelURLsRejectUnknownChannel(t *testing.T) {
	for _, channel := range []string{"dev", "unknown", "../main", "https://example.com", "main/../../dev"} {
		if _, _, err := coreChannelURLs(channel, "dev"); err == nil {
			t.Fatalf("accepted untrusted channel %q", channel)
		}
	}
}
