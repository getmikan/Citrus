package updater

import (
	"errors"
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

func TestInstallRetriesTransientRename(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "citrus")
	update := filepath.Join(dir, "update")
	if err := os.WriteFile(update, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldRename, oldAttempts, oldDelay := renameFile, renameAttempts, renameRetryDelay
	t.Cleanup(func() { renameFile, renameAttempts, renameRetryDelay = oldRename, oldAttempts, oldDelay })
	renameAttempts, renameRetryDelay = 3, 0

	// A scanner holding the new file fails the first renames.
	calls := 0
	renameFile = func(from, to string) error {
		calls++
		if calls < 3 {
			return &os.LinkError{Op: "rename", Old: from, New: to, Err: errors.New("being used by another process")}
		}
		return os.Rename(from, to)
	}
	if err := (&CoreUpdater{}).install(update, current); err != nil {
		t.Fatalf("install after %d renames: %v", calls, err)
	}
	if got, _ := os.ReadFile(current); string(got) != "new" {
		t.Fatalf("install wrote %q", got)
	}

	// A rename that keeps failing gives up after renameAttempts tries.
	calls = 0
	renameFile = func(from, to string) error {
		calls++
		return errors.New("still locked")
	}
	if err := (&CoreUpdater{}).install(update, current); err == nil || calls != 3 {
		t.Fatalf("persistent failure: err=%v after %d renames", err, calls)
	}
	if _, err := os.Stat(current + ".new"); !os.IsNotExist(err) {
		t.Fatalf("failed install left its temp file: %v", err)
	}
}

func TestInstallThroughSymlinkKeepsLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "Cellar-citrus")
	link := filepath.Join(dir, "citrus")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	update := filepath.Join(dir, "update")
	if err := os.WriteFile(update, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := (&CoreUpdater{}).install(update, resolveExePath(link)); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was replaced: %v, %v", fi, err)
	}
	if got, _ := os.ReadFile(link); string(got) != "new" {
		t.Fatalf("link target holds %q", got)
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

// TestCoreBaseNameMatchesAssets checks the name every build variant asks for
// against the asset that build.yml publishes for it.
func TestCoreBaseNameMatchesAssets(t *testing.T) {
	tests := []struct {
		target buildTarget
		want   string
	}{
		{buildTarget{goos: "linux", goarch: "386", go386: "sse2"}, "citrus-linux-386"},
		{buildTarget{goos: "linux", goarch: "386", go386: "softfloat"}, "citrus-linux-386-softfloat"},
		{buildTarget{goos: "windows", goarch: "386"}, "citrus-windows-386"},
		{buildTarget{goos: "linux", goarch: "amd64", goamd64: "v3"}, "citrus-linux-amd64-v3"},
		{buildTarget{goos: "android", goarch: "amd64", goamd64: "v1"}, "citrus-android-amd64"},
		{buildTarget{goos: "linux", goarch: "arm", goarm: "7"}, "citrus-linux-armv7"},
		{buildTarget{goos: "android", goarch: "arm64"}, "citrus-android-arm64-v8"},
		{buildTarget{goos: "linux", goarch: "mipsle", gomips: "softfloat"}, "citrus-linux-mipsle-softfloat"},
		{buildTarget{goos: "linux", goarch: "loong64", loong64ABI: "2"}, "citrus-linux-loong64-abi2"},
		{buildTarget{goos: "linux", goarch: "riscv64"}, "citrus-linux-riscv64"},
	}
	for _, tt := range tests {
		if got := coreBaseName(tt.target); got != tt.want {
			t.Errorf("%+v: got %q, want %q", tt.target, got, tt.want)
		}
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
