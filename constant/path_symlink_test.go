package constant

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathSymlinkEscape(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "missing"), filepath.Join(home, "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := &path{homeDir: home}

	assert.True(t, p.IsSafePath("sub/file.yaml"))
	assert.True(t, p.IsSafePath("new/dir/file.yaml"))
	// Lexically inside home, but the link leads outside.
	assert.False(t, p.IsSafePath("link"))
	assert.False(t, p.IsSafePath("link/file.yaml"))
	assert.False(t, p.IsSafePath(filepath.Join(home, "link", "new", "file.yaml")))
	// Writing through a dangling link would create its target outside.
	assert.False(t, p.IsSafePath("dangling"))

	// A link is fine when its target is itself a safe path.
	p.safePaths = []string{outside}
	assert.True(t, p.IsSafePath("link/file.yaml"))

	// The home directory may itself be a link.
	linkedHome := filepath.Join(outside, "home-link")
	if err := os.Symlink(home, linkedHome); err != nil {
		t.Fatal(err)
	}
	assert.True(t, (&path{homeDir: linkedHome}).IsSafePath("sub/file.yaml"))
	assert.False(t, (&path{homeDir: linkedHome}).IsSafePath("link/file.yaml"))
}
