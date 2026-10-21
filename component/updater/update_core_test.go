package updater

import (
	"net/url"
	"strings"
	"testing"
)

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
