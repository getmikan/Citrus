package resource

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/metacubex/http"
)

const (
	DefaultHttpTimeout = time.Second * 20

	// DefaultSizeLimit caps an HTTP provider download when the provider sets no
	// size-limit (0). Proxy providers are usually kilobytes and the largest
	// public text/yaml rule lists are a few tens of MiB, so 64 MiB leaves ample
	// headroom while keeping a misbehaving or hostile server from making the
	// core buffer an endless body in memory. A provider can raise it with an
	// explicit size-limit, or opt out entirely with size-limit: -1.
	DefaultSizeLimit int64 = 64 << 20

	fileMode os.FileMode = 0o600
	dirMode  os.FileMode = 0o700
)

var (
	etag = false
)

func ETag() bool {
	return etag
}

func SetETag(b bool) {
	etag = b
}

func safeWrite(path string, buf []byte) error {
	dir := filepath.Dir(path)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return err
		}
	}

	// Write a new file next to the target and rename it into place. Rename
	// replaces a symlink at path instead of writing through it, and readers
	// never see a half-written file.
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()
	// os.CreateTemp creates the file with mode 0600 (fileMode).
	if _, err = tmp.Write(buf); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, path); err != nil {
		// Windows refuses to replace a file that another handle holds open.
		// Fall back to writing in place, but only into a regular file.
		if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode().IsRegular() {
			return os.WriteFile(path, buf, fileMode)
		}
		return err
	}
	tmpName = ""
	return nil
}

type FileVehicle struct {
	path string
}

func (f *FileVehicle) Type() P.VehicleType {
	return P.File
}

func (f *FileVehicle) Path() string {
	return f.path
}

func (f *FileVehicle) Url() string {
	return "file://" + f.path
}

func (f *FileVehicle) Read(ctx context.Context, oldHash utils.HashType) (buf []byte, hash utils.HashType, err error) {
	buf, err = os.ReadFile(f.path)
	if err != nil {
		return
	}
	hash = utils.MakeHash(buf)
	return
}

func (f *FileVehicle) Proxy() string {
	return ""
}

func (f *FileVehicle) Write(buf []byte) error {
	return safeWrite(f.path, buf)
}

func NewFileVehicle(path string) *FileVehicle {
	return &FileVehicle{path: path}
}

type HTTPVehicle struct {
	url       string
	path      string
	proxy     string
	header    http.Header
	timeout   time.Duration
	sizeLimit int64
	inRead    func(response *http.Response)
	provider  P.ProxyProvider
}

func (h *HTTPVehicle) Url() string {
	return h.url
}

func (h *HTTPVehicle) Type() P.VehicleType {
	return P.HTTP
}

func (h *HTTPVehicle) Path() string {
	return h.path
}

func (h *HTTPVehicle) Proxy() string {
	return h.proxy
}

func (h *HTTPVehicle) Write(buf []byte) error {
	return safeWrite(h.path, buf)
}

func (h *HTTPVehicle) SetInRead(fn func(response *http.Response)) {
	h.inRead = fn
}

func (h *HTTPVehicle) Read(ctx context.Context, oldHash utils.HashType) (buf []byte, hash utils.HashType, err error) {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	header := h.header
	setIfNoneMatch := false
	if etag && oldHash.IsValid() {
		etagWithHash := cachefile.Cache().GetETagWithHash(h.url)
		if oldHash.Equal(etagWithHash.Hash) && etagWithHash.ETag != "" {
			if header == nil {
				header = http.Header{}
			} else {
				header = header.Clone()
			}
			header.Set("If-None-Match", etagWithHash.ETag)
			setIfNoneMatch = true
		}
	}
	resp, err := mihomoHttp.HttpRequest(ctx, h.url, http.MethodGet, header, nil, mihomoHttp.WithSpecialProxy(h.proxy))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if h.inRead != nil {
		h.inRead(resp)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if setIfNoneMatch && resp.StatusCode == http.StatusNotModified {
			return nil, oldHash, nil
		}
		err = errors.New(resp.Status)
		return
	}
	buf, err = utils.ReadAllLimit(resp.Body, h.effectiveSizeLimit())
	if err != nil {
		buf = nil
		err = fmt.Errorf("response %w", err)
		return
	}
	hash = utils.MakeHash(buf)
	if etag {
		cachefile.Cache().SetETagWithHash(h.url, cachefile.EtagWithHash{
			Hash: hash,
			ETag: resp.Header.Get("ETag"),
			Time: time.Now(),
		})
	}
	return
}

// effectiveSizeLimit maps the configured size-limit onto the cap used for a
// download: a positive value is used as is, 0 selects DefaultSizeLimit and a
// negative value disables the cap.
func (h *HTTPVehicle) effectiveSizeLimit() int64 {
	if h.sizeLimit == 0 {
		return DefaultSizeLimit
	}
	return h.sizeLimit
}

// NewHTTPVehicle creates a vehicle that downloads url. sizeLimit caps the
// response body: a positive value is the cap in bytes, 0 uses
// DefaultSizeLimit and a negative value means no cap. A larger body is an
// error, never silently truncated.
func NewHTTPVehicle(url string, path string, proxy string, header http.Header, timeout time.Duration, sizeLimit int64) *HTTPVehicle {
	return &HTTPVehicle{
		url:       url,
		path:      path,
		proxy:     proxy,
		header:    header,
		timeout:   timeout,
		sizeLimit: sizeLimit,
	}
}
