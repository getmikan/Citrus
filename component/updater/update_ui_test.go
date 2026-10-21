package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/stretchr/testify/require"
)

type archiveEntry struct {
	name string
	size int
}

func makeZip(t *testing.T, entries []archiveEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(make([]byte, e.size)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func makeTgz(t *testing.T, entries []archiveEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(e.size), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(make([]byte, e.size)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func manySmall(n int) []archiveEntry {
	entries := make([]archiveEntry, n)
	for i := range entries {
		entries[i] = archiveEntry{name: fmt.Sprintf("ui/f%04d.js", i), size: 16}
	}
	return entries
}

func TestExtractLimits(t *testing.T) {
	const maxBytes, maxEntries = 64 << 10, 50

	builders := map[string]func(*testing.T, []archiveEntry) []byte{"zip": makeZip, "tgz": makeTgz}
	for kind, build := range builders {
		t.Run(kind, func(t *testing.T) {
			// a normal dashboard-like archive unpacks fine
			ok := build(t, []archiveEntry{{"ui/index.html", 1024}, {"ui/assets/app.js", 32 << 10}})
			if err := extract(ok, t.TempDir(), newExtractBudget(maxBytes, maxEntries)); err != nil {
				t.Fatalf("normal archive: %v", err)
			}

			// too many entries
			err := extract(build(t, manySmall(maxEntries+1)), t.TempDir(), newExtractBudget(maxBytes, maxEntries))
			if err == nil || !strings.Contains(err.Error(), "entries") {
				t.Fatalf("too many entries: %v", err)
			}

			// one highly compressible entry larger than the budget (zip bomb)
			bomb := build(t, []archiveEntry{{"ui/bomb.bin", 1 << 20}})
			if len(bomb) > maxBytes {
				t.Fatalf("bomb archive should be small, got %d bytes", len(bomb))
			}
			err = extract(bomb, t.TempDir(), newExtractBudget(maxBytes, maxEntries))
			if err == nil || !strings.Contains(err.Error(), "unpacks to more than") {
				t.Fatalf("oversized entry: %v", err)
			}

			// many entries each within budget but together over it
			spread := make([]archiveEntry, 10)
			for i := range spread {
				spread[i] = archiveEntry{fmt.Sprintf("ui/chunk%d.bin", i), 8 << 10}
			}
			err = extract(build(t, spread), t.TempDir(), newExtractBudget(maxBytes, maxEntries))
			if err == nil || !strings.Contains(err.Error(), "unpacks to more than") {
				t.Fatalf("total over budget: %v", err)
			}
		})
	}
}

// A zip entry whose header understates its size must not get past the byte
// budget (archive/zip or the budget-enforcing copy rejects it, either way
// nothing much larger than the budget reaches the disk).
func TestUnzipLyingHeader(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateRaw(&zip.FileHeader{Name: "ui/lie.bin", Method: zip.Store, CompressedSize64: 1 << 20, UncompressedSize64: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	err = unzip(buf.Bytes(), dir, newExtractBudget(64<<10, 10))
	if err == nil {
		t.Fatal("want error for an entry that unpacks past the budget")
	}
	if fi, statErr := os.Stat(filepath.Join(dir, "ui", "lie.bin")); statErr == nil && fi.Size() > 64<<10+1 {
		t.Fatalf("wrote %d bytes past the budget", fi.Size())
	}
}

func TestDownloadForBytesLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 2048))
	}))
	defer srv.Close()

	if buf, err := downloadForBytes(srv.URL, 2048); err != nil || len(buf) != 2048 {
		t.Fatalf("within limit: len=%d err=%v", len(buf), err)
	}
	_, err := downloadForBytes(srv.URL, 2047)
	var limitErr *utils.SizeLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("want SizeLimitError, got %v", err)
	}
}

func TestGetLatestVersionLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			_, _ = w.Write(bytes.Repeat([]byte{'v'}, maxVersionFileSize+1))
			return
		}
		_, _ = w.Write([]byte("v1.2.3\n"))
	}))
	defer srv.Close()

	u := &CoreUpdater{}
	if v, err := u.getLatestVersion(srv.URL); err != nil || v != "v1.2.3" {
		t.Fatalf("version: %q %v", v, err)
	}
	_, err := u.getLatestVersion(srv.URL + "/big")
	var limitErr *utils.SizeLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("want SizeLimitError, got %v", err)
	}
}

func TestUIUpdaterRequiresAuthenticatedSource(t *testing.T) {
	archive := makeZip(t, []archiveEntry{{"ui/index.html", 4}})
	u := NewUiUpdater("", "http://ui.example/archive.zip", "", "", false)
	if err := u.validateSource(); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("plaintext source: %v", err)
	}

	u = NewUiUpdater("", "https://ui.example/archive.zip", "", "", false)
	if err := u.validateSource(); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("missing digest: %v", err)
	}

	u = NewUiUpdater("", "http://ui.example/archive.zip", "", strings.Repeat("0", 64), true)
	if err := u.validateSource(); err != nil {
		t.Fatalf("explicit insecure source: %v", err)
	}
	if err := u.verifyArchive(archive); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong digest: %v", err)
	}

	digest := fmt.Sprintf("%x", sha256.Sum256(archive))
	u = NewUiUpdater("", "https://ui.example/archive.zip", "", digest, false)
	if err := u.validateSource(); err != nil {
		t.Fatal(err)
	}
	if err := u.verifyArchive(archive); err != nil {
		t.Fatalf("valid pinned archive: %v", err)
	}
}

func TestUIRootOperationsDoNotFollowReplacedPath(t *testing.T) {
	base := t.TempDir()
	ui := filepath.Join(base, "ui")
	moved := filepath.Join(base, "ui-opened")
	victim := filepath.Join(base, "victim")
	require.NoError(t, os.Mkdir(ui, 0o700))
	require.NoError(t, os.Mkdir(victim, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(ui, "old.js"), []byte("old"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(victim, "keep.txt"), []byte("keep"), 0o600))

	root, err := os.OpenRoot(ui)
	require.NoError(t, err)
	defer root.Close()
	if err := os.Rename(ui, moved); err == nil {
		if err := os.Symlink(victim, ui); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
	}
	require.NoError(t, cleanupRoot(root))
	_, err = os.Stat(filepath.Join(victim, "keep.txt"))
	require.NoError(t, err, "cleanup followed the replaced UI pathname")
}

func TestCopyDirToRootPreservesSingleRootLayout(t *testing.T) {
	staging := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(staging, "bundle"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(staging, "bundle", "index.html"), []byte("ok"), 0o600))
	dest := t.TempDir()
	root, err := os.OpenRoot(dest)
	require.NoError(t, err)
	defer root.Close()
	require.NoError(t, copyDirToRoot(staging, root))
	data, err := os.ReadFile(filepath.Join(dest, "index.html"))
	require.NoError(t, err)
	require.Equal(t, "ok", string(data))
}
