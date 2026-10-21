package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type UIUpdater struct {
	externalUIURL    string
	externalUIPath   string
	externalUISHA256 string
	allowInsecure    bool
	autoDownloadUI   bool

	mutex sync.Mutex
}

type compressionType int

const (
	typeUnknown compressionType = iota
	typeZip
	typeTarGzip
)

func (t compressionType) String() string {
	switch t {
	case typeZip:
		return "zip"
	case typeTarGzip:
		return "tar.gz"
	default:
		return "unknown"
	}
}

// Limits for downloading and unpacking an external UI archive. Current
// dashboards (metacubexd, zashboard, yacd) ship as 1-10 MiB archives that
// unpack to a few hundred files and well under 50 MiB, so these leave a wide
// margin while stopping a decompression bomb or an endless body from
// exhausting memory, disk or inodes.
const (
	// maxUIArchiveSize caps the downloaded archive, which is held in memory.
	maxUIArchiveSize int64 = 64 << 20
	// maxUIExtractedSize caps the sum of all extracted file sizes.
	maxUIExtractedSize int64 = 256 << 20
	// maxUIEntries caps the number of archive entries (files and dirs).
	maxUIEntries = 10000
)

// extractBudget tracks how much an archive may still unpack.
type extractBudget struct {
	maxBytes, bytesLeft int64
	maxEntries, entries int
}

func newExtractBudget(maxBytes int64, maxEntries int) *extractBudget {
	return &extractBudget{maxBytes: maxBytes, bytesLeft: maxBytes, maxEntries: maxEntries}
}

// entry accounts for one more archive entry.
func (b *extractBudget) entry() error {
	b.entries++
	if b.entries > b.maxEntries {
		return fmt.Errorf("archive has more than %d entries", b.maxEntries)
	}
	return nil
}

// copy writes src to dst within the remaining byte budget.
func (b *extractBudget) copy(dst io.Writer, src io.Reader) error {
	n, err := utils.CopyLimit(dst, src, b.bytesLeft)
	b.bytesLeft -= n
	var limitErr *utils.SizeLimitError
	if errors.As(err, &limitErr) {
		return fmt.Errorf("archive unpacks to more than %d bytes", b.maxBytes)
	}
	return err
}

var DefaultUiUpdater = &UIUpdater{}

func NewUiUpdater(externalUI, externalUIURL, externalUIName, externalUISHA256 string, allowInsecure bool) *UIUpdater {
	updater := &UIUpdater{externalUISHA256: strings.TrimSpace(externalUISHA256), allowInsecure: allowInsecure}
	// checkout externalUI exist
	if externalUI != "" {
		updater.autoDownloadUI = true
		updater.externalUIPath = C.Path.Resolve(externalUI)
	} else {
		// default externalUI path
		updater.externalUIPath = path.Join(C.Path.HomeDir(), "ui")
	}

	// checkout UIpath/name exist
	if externalUIName != "" {
		updater.autoDownloadUI = true
		updater.externalUIPath = path.Join(updater.externalUIPath, externalUIName)
	}

	if externalUIURL != "" {
		updater.externalUIURL = externalUIURL
		if allowInsecure {
			log.Warnln("external-ui-allow-insecure explicitly permits an unpinned or plaintext dashboard source")
		}
	}
	return updater
}

func (u *UIUpdater) AutoDownloadUI() {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	if u.autoDownloadUI {
		dirEntries, _ := os.ReadDir(u.externalUIPath)
		if len(dirEntries) > 0 {
			log.Infoln("UI already exists, skip downloading")
		} else {
			log.Infoln("External UI downloading ...")
			err := u.downloadUI()
			if err != nil {
				log.Errorln("Error downloading UI: %s", err)
			}
		}
	}
}

func (u *UIUpdater) DownloadUI() error {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	return u.downloadUI()
}

func (u *UIUpdater) validateSource() error {
	parsedURL, err := url.Parse(u.externalUIURL)
	if err != nil || parsedURL.Host == "" {
		return fmt.Errorf("invalid external-ui-url %q", u.externalUIURL)
	}
	if !strings.EqualFold(parsedURL.Scheme, "https") && !u.allowInsecure {
		return errors.New("external-ui-url must use HTTPS unless external-ui-allow-insecure is true")
	}
	if u.externalUISHA256 == "" && !u.allowInsecure {
		return errors.New("external-ui-sha256 is required unless external-ui-allow-insecure is true")
	}
	return nil
}

func (u *UIUpdater) verifyArchive(data []byte) error {
	if u.externalUISHA256 == "" {
		return nil
	}
	expected, err := hex.DecodeString(u.externalUISHA256)
	if err != nil || len(expected) != sha256.Size {
		return errors.New("external-ui-sha256 must be a 64-character SHA-256 hex digest")
	}
	actual := sha256.Sum256(data)
	if !bytes.Equal(actual[:], expected) {
		return errors.New("external UI archive SHA-256 does not match external-ui-sha256")
	}
	return nil
}

func detectFileType(data []byte) compressionType {
	if len(data) < 4 {
		return typeUnknown
	}

	// Zip: 0x50 0x4B 0x03 0x04
	if data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04 {
		return typeZip
	}

	// GZip: 0x1F 0x8B
	if data[0] == 0x1F && data[1] == 0x8B {
		return typeTarGzip
	}

	return typeUnknown
}

func (u *UIUpdater) downloadUI() error {
	// Checked here, with symlinks resolved, because the directory is about
	// to be emptied and refilled: a link planted under the UI path must not
	// redirect that outside the safe paths.
	if !C.Path.IsSafePath(u.externalUIPath) {
		return C.Path.ErrNotSafePath(u.externalUIPath)
	}
	if err := u.validateSource(); err != nil {
		return err
	}
	data, err := downloadForBytes(u.externalUIURL, maxUIArchiveSize)
	if err != nil {
		return fmt.Errorf("can't download file: %w", err)
	}
	if err := u.verifyArchive(data); err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp("", "citrus-ui-")
	if err != nil {
		return fmt.Errorf("create private UI staging directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	log.Debugln("extractedFolder: %s", tmpDir)
	err = extract(data, tmpDir, newExtractBudget(maxUIExtractedSize, maxUIEntries))
	if err != nil {
		return fmt.Errorf("can't extract compressed file: %w", err)
	}

	if C.Path.HoldsCoreState(u.externalUIPath) { // never empty the home or config directory
		return fmt.Errorf("refusing to replace %s: it holds the files of the core", u.externalUIPath)
	}
	if err = u.prepareUIPath(); err != nil {
		return fmt.Errorf("prepare UI path failed: %w", err)
	}
	root, err := openVerifiedUIRoot(u.externalUIPath)
	if err != nil {
		return err
	}
	defer root.Close()
	if err = cleanupRoot(root); err != nil {
		return fmt.Errorf("cleanup existing UI: %w", err)
	}
	if err = copyDirToRoot(tmpDir, root); err != nil {
		return fmt.Errorf("install UI: %w", err)
	}
	return nil
}

func (u *UIUpdater) prepareUIPath() error {
	if _, err := os.Stat(u.externalUIPath); os.IsNotExist(err) {
		log.Infoln("dir %s does not exist, creating", u.externalUIPath)
		if err := os.MkdirAll(u.externalUIPath, os.ModePerm); err != nil {
			log.Warnln("create dir %s error: %s", u.externalUIPath, err)
		}
	}
	return nil
}

func openVerifiedUIRoot(path string) (*os.Root, error) {
	if !C.Path.IsSafePath(path) {
		return nil, C.Path.ErrNotSafePath(path)
	}
	if C.Path.HoldsCoreState(path) {
		return nil, fmt.Errorf("refusing to replace %s: it holds the files of the core", path)
	}
	before, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() {
		return nil, fmt.Errorf("external UI path is not a directory: %s", path)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		root.Close()
		return nil, errors.New("external UI path changed while opening it")
	}
	if !C.Path.IsSafePath(path) || C.Path.HoldsCoreState(path) {
		root.Close()
		return nil, errors.New("external UI path became unsafe while opening it")
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(after, opened) {
		root.Close()
		return nil, errors.New("external UI path changed while opening it")
	}
	return root, nil
}

func unzip(data []byte, dest string, budget *extractBudget) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}

	// check whether or not only exists singleRoot dir

	for _, f := range r.File {
		if err = budget.entry(); err != nil {
			return err
		}
		fpath := filepath.Join(dest, f.Name)

		if !inDest(fpath, dest) {
			return fmt.Errorf("invalid file path: %s", fpath)
		}
		info := f.FileInfo()
		if info.IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue // disallow symlink
		}
		// The declared size can lie (the copy below enforces the real one),
		// but an honest oversized entry is rejected before anything is written.
		if f.UncompressedSize64 > uint64(budget.bytesLeft) {
			return fmt.Errorf("archive unpacks to more than %d bytes", budget.maxBytes)
		}
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode().Perm())
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		err = budget.copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func untgz(data []byte, dest string, budget *extractBudget) error {
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if err = budget.entry(); err != nil {
			return err
		}

		fpath := filepath.Join(dest, header.Name)

		if !inDest(fpath, dest) {
			return fmt.Errorf("invalid file path: %s", fpath)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(fpath, os.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
				return err
			}
			outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode).Perm())
			if err != nil {
				return err
			}
			if err := budget.copy(outFile, tr); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
		}
	}
	return nil
}

func extract(data []byte, dest string, budget *extractBudget) error {
	fileType := detectFileType(data)
	log.Debugln("compression Type: %s", fileType)
	switch fileType {
	case typeZip:
		return unzip(data, dest, budget)
	case typeTarGzip:
		return untgz(data, dest, budget)
	default:
		return fmt.Errorf("unknown or unsupported file type")
	}
}

func cleanTarPath(path string) string {
	// remove prefix ./ or ../
	path = strings.TrimPrefix(path, "./")
	path = strings.TrimPrefix(path, "../")

	// normalize path
	path = filepath.Clean(path)

	// transfer delimiters to system std
	path = filepath.FromSlash(path)

	// remove prefix path delimiters
	path = strings.TrimPrefix(path, string(os.PathSeparator))

	return path
}

func cleanupRoot(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err = root.RemoveAll(entry.Name()); err != nil {
			return err
		}
	}
	return nil
}

func copyDirToRoot(src string, dst *os.Root) error {
	dirEntryList, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	if len(dirEntryList) == 1 && dirEntryList[0].IsDir() {
		src = filepath.Join(src, dirEntryList[0].Name())
		log.Debugln("match the singleRoot: %s", src)
		dirEntryList, err = os.ReadDir(src)
		if err != nil {
			return err
		}
	}

	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		fpath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if fpath == "." {
			return nil
		}
		if !filepath.IsLocal(fpath) {
			return &os.PathError{Op: "Copy", Path: fpath, Err: os.ErrInvalid}
		}

		switch info.Mode().Type() {
		case os.ModeDir:
			return dst.MkdirAll(fpath, info.Mode().Perm())
		case os.ModeSymlink:
			return &os.PathError{Op: "Copy", Path: fpath, Err: errors.New("symlinks are not allowed in UI staging")}
		case 0:
			if err := dst.MkdirAll(filepath.Dir(fpath), 0o755); err != nil && filepath.Dir(fpath) != "." {
				return err
			}
			r, err := os.Open(path)
			if err != nil {
				return err
			}
			defer r.Close()
			w, err := dst.OpenFile(fpath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
			if err != nil {
				return err
			}

			if _, err := io.Copy(w, r); err != nil {
				w.Close()
				return &os.PathError{Op: "Copy", Path: fpath, Err: err}
			}
			return w.Close()
		default:
			return &os.PathError{Op: "CopyFS", Path: path, Err: os.ErrInvalid}
		}
	})
}

func inDest(fpath, dest string) bool {
	if rel, err := filepath.Rel(dest, fpath); err == nil {
		if filepath.IsLocal(rel) {
			return true
		}
	}
	return false
}
