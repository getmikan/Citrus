package updater

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

const (
	baseReleaseURL = "https://github.com/getmikan/Citrus/releases/latest/download/"
	baseMainURL    = "https://github.com/getmikan/Citrus/releases/download/Prerelease-main/"
	baseDevURL     = "https://github.com/getmikan/Citrus/releases/download/Prerelease-dev/"

	// MaxPackageFileSize is a maximum package file length in bytes. The largest
	// package whose size is limited by this constant currently has the size of
	// approximately 32 MiB.
	MaxPackageFileSize = 32 * 1024 * 1024

	// MaxUnpackedFileSize caps the binary extracted from a package. Citrus
	// binaries are 30-60 MiB uncompressed; the margin keeps future growth safe
	// while a crafted package can no longer expand without bound on disk.
	MaxUnpackedFileSize = 256 * 1024 * 1024

	// maxVersionFileSize caps the version.txt response, which holds a single
	// short version string.
	maxVersionFileSize = 64 * 1024

	// maxChecksumsFileSize caps checksums.txt: one "sha256  ./name" line per
	// release asset, a few hundred lines today.
	maxChecksumsFileSize = 1024 * 1024

	// checksumsFileName is the SHA-256 list the release workflow publishes
	// next to the packages.
	checksumsFileName = "checksums.txt"
)

// versionPattern is what version.txt may contain: a release tag ("v1.2.3")
// or a prerelease build name ("main-abc1234"). The version becomes part of a
// file name and a URL, so anything else (path separators, "..", URL
// delimiters, whitespace) is rejected.
var versionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,127}$`)

func validVersion(version string) bool {
	return versionPattern.MatchString(version) && !strings.Contains(version, "..")
}

const (
	ReleaseChannel = "release"
	AlphaChannel   = "alpha"
	MainChannel    = "main"
	DevChannel     = "dev"
)

// CoreUpdater is the citrus updater.
// modify from https://github.com/AdguardTeam/AdGuardHome/blob/595484e0b3fb4c457f9bb727a6b94faa78a66c5f/internal/updater/updater.go
type CoreUpdater struct {
	mu sync.Mutex
}

var DefaultCoreUpdater = CoreUpdater{}

func coreChannelURLs(channel, version string) (baseURL, versionURL string, err error) {
	channel, err = effectiveUpdateChannel(channel, version)
	if err != nil {
		return "", "", err
	}
	switch channel {
	case MainChannel, AlphaChannel:
		baseURL = baseMainURL
	case DevChannel:
		baseURL = baseDevURL
	case ReleaseChannel:
		baseURL = baseReleaseURL
	}
	return baseURL, baseURL + updateManifestFileName, nil
}

func effectiveUpdateChannel(channel, version string) (string, error) {
	channel = strings.ToLower(channel)
	if channel == "" || channel == "auto" {
		switch {
		case version == "main", strings.HasPrefix(version, "main-"), strings.HasPrefix(version, "alpha-"):
			channel = MainChannel
		case version == "dev", strings.HasPrefix(version, "dev-"):
			channel = DevChannel
		default:
			channel = ReleaseChannel
		}
	}
	switch channel {
	case AlphaChannel:
		return MainChannel, nil
	case MainChannel:
	case DevChannel:
		return "", errors.New("update error: dev self-update is unavailable because the dev branch does not publish signed release artifacts")
	case ReleaseChannel:
	default:
		return "", fmt.Errorf("update error: unsupported channel %q", channel)
	}
	return channel, nil
}

func (u *CoreUpdater) CoreBaseName() string {
	switch runtime.GOARCH {
	case "arm":
		// citrus-linux-armv5
		return fmt.Sprintf("citrus-%s-%sv%s", runtime.GOOS, runtime.GOARCH, features.GOARM)
	case "arm64":
		if runtime.GOOS == "android" {
			// citrus-android-arm64-v8
			return fmt.Sprintf("citrus-%s-%s-v8", runtime.GOOS, runtime.GOARCH)
		}
		// citrus-linux-arm64
		return fmt.Sprintf("citrus-%s-%s", runtime.GOOS, runtime.GOARCH)
	case "mips", "mipsle":
		// citrus-linux-mips-hardfloat
		return fmt.Sprintf("citrus-%s-%s-%s", runtime.GOOS, runtime.GOARCH, features.GOMIPS)
	case "amd64":
		if runtime.GOOS == "android" {
			// citrus-android-amd64
			return fmt.Sprintf("citrus-%s-%s", runtime.GOOS, runtime.GOARCH)
		}
		// citrus-linux-amd64-v1
		return fmt.Sprintf("citrus-%s-%s-%s", runtime.GOOS, runtime.GOARCH, features.GOAMD64)
	default:
		// citrus-linux-386
		// citrus-linux-mips64
		// citrus-linux-riscv64
		// citrus-linux-s390x
		return fmt.Sprintf("citrus-%s-%s", runtime.GOOS, runtime.GOARCH)
	}
}

func (u *CoreUpdater) Update(currentExePath string, channel string, force bool) (err error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	info, err := os.Stat(currentExePath)
	if err != nil {
		return fmt.Errorf("check currentExePath %q: %w", currentExePath, err)
	}

	effectiveChannel, err := effectiveUpdateChannel(channel, C.Version)
	if err != nil {
		return err
	}
	baseURL, manifestURL, err := coreChannelURLs(effectiveChannel, C.Version)
	if err != nil {
		return err
	}
	manifestBytes, err := u.fetchMetadata(manifestURL, maxUpdateManifestSize)
	if err != nil {
		return fmt.Errorf("get update manifest: %w", err)
	}
	signatureBytes, err := u.fetchMetadata(baseURL+updateSignatureFileName, maxUpdateSignatureSize)
	if err != nil {
		return fmt.Errorf("get update signature: %w", err)
	}
	manifest, artifact, err := verifyUpdateManifest(manifestBytes, signatureBytes, effectiveChannel, u.CoreBaseName(), loadUpdateSequence(effectiveChannel), time.Now())
	if err != nil {
		return fmt.Errorf("verify update manifest: %w", err)
	}
	latestVersion := manifest.Version
	log.Infoln("current version %s, latest version %s", C.Version, latestVersion)

	if latestVersion == C.Version && !force {
		// don't change this output, some downstream dependencies on the upgrader's output fields
		return fmt.Errorf("update error: already using latest version %s", C.Version)
	}

	defer func() {
		if err != nil {
			log.Errorln("updater: failed: %v", err)
		} else {
			log.Infoln("updater: finished")
		}
	}()

	// ---- prepare ----
	// Every name below comes from the validated version and constants;
	// nothing stored inside the downloaded archive names a file on disk.
	mihomoBaseName := u.CoreBaseName()
	packageName := artifact.Name
	packageURL := baseURL + packageName
	log.Infoln("updater: updating using url: %s", packageURL)

	workDir := filepath.Dir(currentExePath)
	backupDir := filepath.Join(workDir, "citrus-backup")
	updateDir := filepath.Join(workDir, "citrus-update")
	packagePath := filepath.Join(updateDir, packageName)

	updateExeName := mihomoBaseName
	if runtime.GOOS == "windows" {
		updateExeName = updateExeName + ".exe"
	}
	log.Infoln("updateExeName: %s", updateExeName)
	updateExePath := filepath.Join(updateDir, updateExeName)
	backupExePath := filepath.Join(backupDir, filepath.Base(currentExePath))

	defer u.clean(updateDir)

	err = u.download(updateDir, packagePath, packageURL)
	if err != nil {
		return fmt.Errorf("downloading: %w", err)
	}

	err = checkManifestArtifact(packagePath, artifact)
	if err != nil {
		return fmt.Errorf("verifying: %w", err)
	}

	err = u.unpack(packagePath, updateExePath, info.Mode())
	if err != nil {
		return fmt.Errorf("unpacking: %w", err)
	}

	err = u.backup(currentExePath, backupExePath, backupDir)
	if err != nil {
		return fmt.Errorf("backuping: %w", err)
	}

	err = u.copyFile(updateExePath, currentExePath)
	if err != nil {
		return fmt.Errorf("replacing: %w", err)
	}
	if err = saveUpdateSequence(effectiveChannel, manifest.Sequence); err != nil {
		_ = u.copyFile(backupExePath, currentExePath)
		return fmt.Errorf("persisting anti-rollback state (executable restored): %w", err)
	}

	return nil
}

func (u *CoreUpdater) fetchMetadata(url string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, url, http.MethodGet, nil, nil, mihomoHttp.WithCAOption(ca.Option{ZeroTrust: true}))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, errors.New(resp.Status)
	}
	return utils.ReadAllLimit(resp.Body, limit)
}

func checkManifestArtifact(path string, artifact updateArtifact) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Size() != artifact.Size {
		return fmt.Errorf("%s: size %d does not match signed manifest (%d)", artifact.Name, info.Size(), artifact.Size)
	}
	want, _ := hex.DecodeString(artifact.SHA256)
	return checkFileSHA256(path, artifact.Name, want)
}

func (u *CoreUpdater) getLatestVersion(versionURL string) (version string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, versionURL, http.MethodGet, nil, nil, mihomoHttp.WithCAOption(ca.Option{ZeroTrust: true}))
	if err != nil {
		return "", err
	}
	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("version file: %s", resp.Status)
	}

	body, err := utils.ReadAllLimit(resp.Body, maxVersionFileSize)
	if err != nil {
		return "", fmt.Errorf("version file: %w", err)
	}
	content := strings.TrimSpace(string(body))
	if !validVersion(content) {
		return "", fmt.Errorf("version file: invalid version %q", truncateForLog(content))
	}
	return content, nil
}

func truncateForLog(s string) string {
	const max = 64
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// verify checks the downloaded package against the SHA-256 that the release
// lists in checksums.txt. Both files come from the same release, so this
// catches truncated, corrupted or mismatched downloads and an asset replaced
// without updating the list; it does not prove who published the release.
// A detached signature over checksums.txt, checked against a key built into
// Citrus, is the planned next step.
func (u *CoreUpdater) verify(checksumsURL, packageName, packagePath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, checksumsURL, http.MethodGet, nil, nil, mihomoHttp.WithCAOption(ca.Option{ZeroTrust: true}))
	if err != nil {
		return fmt.Errorf("checksums: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("checksums: %s", resp.Status)
	}
	list, err := utils.ReadAllLimit(resp.Body, maxChecksumsFileSize)
	if err != nil {
		return fmt.Errorf("checksums: %w", err)
	}
	want, err := findChecksum(list, packageName)
	if err != nil {
		return err
	}
	return checkFileSHA256(packagePath, packageName, want)
}

func checkFileSHA256(path, name string, want []byte) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return err
	}
	if got := h.Sum(nil); !bytes.Equal(got, want) {
		return fmt.Errorf("%s: SHA-256 %x does not match checksums.txt (%x)", name, got, want)
	}
	log.Infoln("updater: %s matches checksums.txt", name)
	return nil
}

// findChecksum returns the SHA-256 that a sha256sum-style list gives for
// name. Lines look like "<64 hex>  ./name" or "<64 hex> *name".
func findChecksum(list []byte, name string) ([]byte, error) {
	var found []byte
	sc := bufio.NewScanner(bytes.NewReader(list))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		file := strings.TrimPrefix(strings.TrimPrefix(fields[1], "*"), "./")
		if file != name {
			continue
		}
		sum, err := hex.DecodeString(fields[0])
		if err != nil || len(sum) != sha256.Size {
			return nil, fmt.Errorf("checksums: malformed entry for %s", name)
		}
		if found != nil && !bytes.Equal(found, sum) {
			return nil, fmt.Errorf("checksums: conflicting entries for %s", name)
		}
		found = sum
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("checksums: %w", err)
	}
	if found == nil {
		return nil, fmt.Errorf("checksums: no entry for %s", name)
	}
	return found, nil
}

// download package file and save it to disk
func (u *CoreUpdater) download(updateDir, packagePath, packageURL string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*90)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, packageURL, http.MethodGet, nil, nil, mihomoHttp.WithCAOption(ca.Option{ZeroTrust: true}))
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("http request failed: %s", resp.Status)
	}

	log.Debugln("updateDir %s", updateDir)
	// A directory left by an interrupted update may hold anything, symlinks
	// included: start from an empty one created by this process.
	_ = os.RemoveAll(updateDir)
	err = os.Mkdir(updateDir, 0o700)
	if err != nil {
		return fmt.Errorf("mkdir error: %w", err)
	}

	log.Debugln("updater: saving package to file %s", packagePath)
	// Create the output file
	wc, err := createExclusive(packagePath, 0o600)
	if err != nil {
		return fmt.Errorf("os.OpenFile(%s): %w", packagePath, err)
	}

	defer func() {
		closeErr := wc.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	log.Debugln("updater: reading http body")
	// CopyLimit reads at most one byte past MaxPackageFileSize, so a package
	// of exactly the limit is accepted and anything larger is an error.
	_, err = utils.CopyLimit(wc, resp.Body, MaxPackageFileSize)
	if err != nil {
		return fmt.Errorf("package: %w", err)
	}
	log.Debugln("updater: downloaded package to file %s", packagePath)

	return nil
}

// unpack extracts the executable from the downloaded package to outPath. The
// file name stored in the package is ignored.
func (u *CoreUpdater) unpack(packagePath, outPath string, fileMode os.FileMode) error {
	log.Infoln("updater: unpacking package")
	if strings.HasSuffix(packagePath, ".zip") {
		err := u.zipFileUnpack(packagePath, outPath, fileMode)
		if err != nil {
			return fmt.Errorf(".zip unpack failed: %w", err)
		}

	} else if strings.HasSuffix(packagePath, ".gz") {
		err := u.gzFileUnpack(packagePath, outPath, fileMode)
		if err != nil {
			return fmt.Errorf(".gz unpack failed: %w", err)
		}

	} else {
		return fmt.Errorf("unknown package extension")
	}

	return nil
}

// backup creates a backup of the current executable file.
func (u *CoreUpdater) backup(currentExePath, backupExePath, backupDir string) (err error) {
	log.Infoln("updater: backing up current ExecFile:%s to %s", currentExePath, backupExePath)
	_ = os.Mkdir(backupDir, 0o755)

	// On Windows, since the running executable cannot be overwritten or deleted, it uses os.Rename to move the file to the backup path.
	// On other platforms, it copies the file to the backup path, preserving the original file and its permissions.
	// The backup directory is created if it does not exist.
	if runtime.GOOS == "windows" {
		err = os.Rename(currentExePath, backupExePath)
	} else {
		err = u.copyFile(currentExePath, backupExePath)
	}
	if err != nil {
		return err
	}

	return nil
}

// clean removes the temporary directory itself and all it's contents.
func (u *CoreUpdater) clean(updateDir string) {
	_ = os.RemoveAll(updateDir)
}

// createExclusive creates path for writing and fails if anything, a symlink
// included, already exists there.
func createExclusive(path string, fileMode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
}

// gzFileUnpack decompresses a single .gz file to outPath. The original file
// name in the gzip header is ignored.
func (u *CoreUpdater) gzFileUnpack(gzfile, outPath string, fileMode os.FileMode) (err error) {
	f, err := os.Open(gzfile)
	if err != nil {
		return fmt.Errorf("os.Open(): %w", err)
	}

	defer func() {
		closeErr := f.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip.NewReader(): %w", err)
	}

	defer func() {
		closeErr := gzReader.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	wc, err := createExclusive(outPath, fileMode)
	if err != nil {
		return fmt.Errorf("os.OpenFile(%s): %w", outPath, err)
	}

	defer func() {
		closeErr := wc.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	// Copy the contents of the gzReader to the output file
	_, err = utils.CopyLimit(wc, gzReader, MaxUnpackedFileSize)
	if err != nil {
		return fmt.Errorf("io.Copy(): %w", err)
	}

	return nil
}

// zipFileUnpack extracts the only file of a .zip package to outPath. The
// entry name stored in the archive is ignored.
func (u *CoreUpdater) zipFileUnpack(zipfile, outPath string, fileMode os.FileMode) (err error) {
	zrc, err := zip.OpenReader(zipfile)
	if err != nil {
		return fmt.Errorf("zip.OpenReader(): %w", err)
	}

	defer func() {
		closeErr := zrc.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	if len(zrc.File) != 1 {
		return fmt.Errorf("expected one file in the zip archive, found %d", len(zrc.File))
	}

	zf := zrc.File[0]
	if !zf.Mode().IsRegular() {
		return errors.New("the zip entry is not a regular file")
	}
	var rc io.ReadCloser
	rc, err = zf.Open()
	if err != nil {
		return fmt.Errorf("zip file Open(): %w", err)
	}

	defer func() {
		closeErr := rc.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	wc, err := createExclusive(outPath, fileMode)
	if err != nil {
		return fmt.Errorf("os.OpenFile(): %w", err)
	}

	defer func() {
		closeErr := wc.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	_, err = utils.CopyLimit(wc, rc, MaxUnpackedFileSize)
	if err != nil {
		return fmt.Errorf("io.Copy(): %w", err)
	}

	return nil
}

// Copy file on disk
func (u *CoreUpdater) copyFile(src, dst string) (err error) {
	rc, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("os.Open(%s): %w", src, err)
	}

	defer func() {
		closeErr := rc.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	info, err := rc.Stat()
	if err != nil {
		return fmt.Errorf("rc.Stat(): %w", err)
	}

	// Create the output file
	// If the file does not exist, creates it with permissions perm (before umask);
	// otherwise truncates it before writing, without changing permissions.
	wc, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode())
	if err != nil {
		// On some file system (such as Android's /data) maybe return error: "text file busy"
		// Let's delete the target file and recreate it
		err = os.Remove(dst)
		if err != nil {
			return fmt.Errorf("os.Remove(%s): %w", dst, err)
		}
		wc, err = os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode())
		if err != nil {
			return fmt.Errorf("os.OpenFile(%s): %w", dst, err)
		}
	}

	defer func() {
		closeErr := wc.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	_, err = io.Copy(wc, rc)
	if err != nil {
		return fmt.Errorf("io.Copy(): %w", err)
	}

	if runtime.GOOS == "darwin" {
		err = exec.Command("/usr/bin/codesign", "--sign", "-", dst).Run()
		if err != nil {
			log.Warnln("codesign failed: %v", err)
		}
	}

	log.Infoln("updater: copy: %s to %s", src, dst)
	return nil
}
