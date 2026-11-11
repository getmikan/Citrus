package geodata

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/stretchr/testify/require"
)

func TestDownloadToPathLimit(t *testing.T) {
	payload := bytes.Repeat([]byte{'g'}, 4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "GeoSite.dat")

	// A longer stale file must be fully replaced, not overwritten in place
	// leaving its tail behind.
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, 10000), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := downloadToPathLimit(srv.URL, path, int64(len(payload))); err != nil {
		t.Fatalf("download within limit: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("file has %d bytes, want exactly the %d downloaded", len(got), len(payload))
	}

	// Oversized: error, the existing file is untouched and no temp file stays.
	err = downloadToPathLimit(srv.URL, path, int64(len(payload))-1)
	var limitErr *utils.SizeLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("want SizeLimitError, got %v", err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, payload) {
		t.Fatal("oversized download modified the existing file")
	}

	// HTTP errors are not written to disk.
	missing := filepath.Join(dir, "GeoIP.dat")
	if err := downloadToPathLimit(srv.URL+"/missing", missing, DownloadSizeLimit); err == nil {
		t.Fatal("want error for 404")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("404 left a file behind: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}

func TestAuthenticatedDownloadPreservesOldFileOnPinFailure(t *testing.T) {
	oldPolicy := CurrentVerificationPolicy()
	t.Cleanup(func() { SetVerificationPolicy(oldPolicy) })
	SetVerificationPolicy(VerificationPolicy{GeoSite: strings.Repeat("0", 64)})
	payload := []byte("candidate")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(payload) }))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "GeoSite.dat")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o600))
	err := downloadToPathLimitVerified(srv.URL, path, 1024, AssetGeoSite, nil)
	require.ErrorIs(t, err, ErrAssetPinMismatch)
	got, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, "old", string(got))
}
