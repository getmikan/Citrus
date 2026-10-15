package updater

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidVersion(t *testing.T) {
	for _, v := range []string{"v1.2.3", "v0.0.0", "main-abc1234", "dev-0123abc", "alpha-1a2b3c", "v1.2.3-rc.1+meta"} {
		if !validVersion(v) {
			t.Errorf("rejected %q", v)
		}
	}
	for _, v := range []string{"", "../../etc/passwd", "v1/../../x", "v1..2", "v1.2.3#frag", "v1 2", "v1?x=1", `v1\x`, ".hidden", "-v1", strings.Repeat("a", 129), "v1\n"} {
		if validVersion(v) {
			t.Errorf("accepted %q", v)
		}
	}
}

func TestGetLatestVersionRejectsBadVersions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/traversal":
			_, _ = w.Write([]byte("../../../tmp/x#\n"))
		case "/missing":
			http.NotFound(w, r)
		default:
			_, _ = w.Write([]byte("  main-abc1234\r\n"))
		}
	}))
	defer srv.Close()

	u := &CoreUpdater{}
	if v, err := u.getLatestVersion(srv.URL); err != nil || v != "main-abc1234" {
		t.Fatalf("version: %q %v", v, err)
	}
	if _, err := u.getLatestVersion(srv.URL + "/traversal"); err == nil {
		t.Fatal("accepted a path-like version")
	}
	if _, err := u.getLatestVersion(srv.URL + "/missing"); err == nil {
		t.Fatal("accepted a 404 body as a version")
	}
}

func TestFindChecksum(t *testing.T) {
	sum := sha256.Sum256([]byte("pkg"))
	other := sha256.Sum256([]byte("other"))
	list := fmt.Sprintf("%x  ./citrus-linux-amd64-v1-v1.0.0.gz\n%x *citrus-windows-amd64-v1-v1.0.0.zip\n", sum, other)

	got, err := findChecksum([]byte(list), "citrus-linux-amd64-v1-v1.0.0.gz")
	if err != nil || !bytes.Equal(got, sum[:]) {
		t.Fatalf("gz entry: %x %v", got, err)
	}
	got, err = findChecksum([]byte(list), "citrus-windows-amd64-v1-v1.0.0.zip")
	if err != nil || !bytes.Equal(got, other[:]) {
		t.Fatalf("zip entry: %x %v", got, err)
	}
	if _, err = findChecksum([]byte(list), "citrus-linux-arm64-v1.0.0.gz"); err == nil {
		t.Fatal("found a checksum for an unlisted package")
	}
	conflict := list + fmt.Sprintf("%x  ./citrus-linux-amd64-v1-v1.0.0.gz\n", other)
	if _, err = findChecksum([]byte(conflict), "citrus-linux-amd64-v1-v1.0.0.gz"); err == nil {
		t.Fatal("accepted conflicting entries")
	}
	if _, err = findChecksum([]byte("abcd  ./citrus-linux-amd64-v1-v1.0.0.gz\n"), "citrus-linux-amd64-v1-v1.0.0.gz"); err == nil {
		t.Fatal("accepted a short digest")
	}
}

func TestVerifyPackage(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "citrus-linux-amd64-v1-v1.0.0.gz")
	if err := os.WriteFile(pkg, []byte("package bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	good := sha256.Sum256([]byte("package bytes"))
	bad := sha256.Sum256([]byte("tampered"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/good/checksums.txt":
			fmt.Fprintf(w, "%x  ./citrus-linux-amd64-v1-v1.0.0.gz\n", good)
		case "/bad/checksums.txt":
			fmt.Fprintf(w, "%x  ./citrus-linux-amd64-v1-v1.0.0.gz\n", bad)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u := &CoreUpdater{}
	if err := u.verify(srv.URL+"/good/checksums.txt", filepath.Base(pkg), pkg); err != nil {
		t.Fatalf("matching checksum: %v", err)
	}
	if err := u.verify(srv.URL+"/bad/checksums.txt", filepath.Base(pkg), pkg); err == nil {
		t.Fatal("accepted a mismatching checksum")
	}
	if err := u.verify(srv.URL+"/none/checksums.txt", filepath.Base(pkg), pkg); err == nil {
		t.Fatal("accepted a release without checksums.txt")
	}
}

func TestGzUnpackIgnoresHeaderName(t *testing.T) {
	dir := t.TempDir()
	stage := filepath.Join(dir, "citrus-update")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Name = "../escaped"
	_, _ = zw.Write([]byte("binary"))
	_ = zw.Close()
	pkg := filepath.Join(stage, "pkg.gz")
	if err := os.WriteFile(pkg, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(stage, "citrus-linux-amd64")
	u := &CoreUpdater{}
	if err := u.gzFileUnpack(pkg, out, 0o755); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(out); err != nil || string(data) != "binary" {
		t.Fatalf("output: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "escaped")); !os.IsNotExist(err) {
		t.Fatalf("header name was used as a path: %v", err)
	}
	// A pre-existing file (or symlink) at the output is never reused.
	if err := u.gzFileUnpack(pkg, out, 0o755); err == nil {
		t.Fatal("overwrote an existing output file")
	}
}

func TestZipUnpackIgnoresEntryName(t *testing.T) {
	dir := t.TempDir()
	stage := filepath.Join(dir, "citrus-update")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	makeZip := func(names ...string) string {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for _, n := range names {
			w, _ := zw.Create(n)
			_, _ = w.Write([]byte("exe"))
		}
		_ = zw.Close()
		p := filepath.Join(stage, fmt.Sprintf("pkg%d.zip", len(names)))
		if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	u := &CoreUpdater{}
	out := filepath.Join(stage, "citrus-windows-amd64.exe")
	if err := u.zipFileUnpack(makeZip("../../escaped.exe"), out, 0o755); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(out); err != nil || string(data) != "exe" {
		t.Fatalf("output: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "escaped.exe")); !os.IsNotExist(err) {
		t.Fatalf("entry name was used as a path: %v", err)
	}
	if err := u.zipFileUnpack(makeZip("a.exe", "b.exe"), filepath.Join(stage, "two.exe"), 0o755); err == nil {
		t.Fatal("accepted a zip with more than one file")
	}
}
