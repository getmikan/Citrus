//go:build unix

package age

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWritePrivateFile(t *testing.T) {
	oldMask := syscall.Umask(0o022)
	defer syscall.Umask(oldMask)

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// An existing, world-readable target is replaced by an owner-only file.
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFile(path, []byte("secret: x")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
	if data, _ := os.ReadFile(path); string(data) != "secret: x" {
		t.Fatalf("content %q", data)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("temporary file left behind: %v", entries)
	}
}
