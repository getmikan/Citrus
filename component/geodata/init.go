package geodata

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/utils"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

var (
	initGeoSite bool
	initGeoIP   int
	initASN     bool

	initGeoSiteMutex sync.Mutex
	initGeoIPMutex   sync.Mutex
	initASNMutex     sync.Mutex

	geoIpEnable   atomic.Bool
	geoSiteEnable atomic.Bool
	asnEnable     atomic.Bool

	geoIpUrl   string
	mmdbUrl    string
	geoSiteUrl string
	asnUrl     string
)

func GeoIpUrl() string {
	return geoIpUrl
}

func SetGeoIpUrl(url string) {
	geoIpUrl = url
}

func MmdbUrl() string {
	return mmdbUrl
}

func SetMmdbUrl(url string) {
	mmdbUrl = url
}

func GeoSiteUrl() string {
	return geoSiteUrl
}

func SetGeoSiteUrl(url string) {
	geoSiteUrl = url
}

func ASNUrl() string {
	return asnUrl
}

func SetASNUrl(url string) {
	asnUrl = url
}

// DownloadSizeLimit caps a single GEO database download (GeoIP.dat,
// GeoSite.dat, MMDB, ASN). The stock databases are 2-25 MiB; the limit is set
// well above that so that a city-level MMDB (GeoLite2-City is ~70 MiB,
// dbip-city-lite ~130 MiB) configured as mmdb-url still fits, while an endless
// or hostile response can no longer fill the disk or the memory of the
// updater, which buffers the whole file.
const DownloadSizeLimit int64 = 256 << 20

func downloadToPath(asset AssetType, url string, path string, validator func(string) error) error {
	return downloadToPathLimitVerified(url, path, DownloadSizeLimit, asset, validator)
}

// downloadToPathLimit downloads url into a temporary file next to path and
// renames it into place only once the whole body has arrived within limit, so
// a failed or oversized download never leaves a partial file (or the stale
// tail of an older, longer file) at path.
func downloadToPathLimit(url string, path string, limit int64) (err error) {
	return downloadToPathLimitVerified(url, path, limit, "", nil)
}

func downloadToPathLimitVerified(url string, path string, limit int64, asset AssetType, validator func(string) error) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*90)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, url, http.MethodGet, nil, nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errors.New(resp.Status)
	}

	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	h := sha256.New()
	_, err = utils.CopyLimit(io.MultiWriter(f, h), resp.Body, limit)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		var limitErr *utils.SizeLimitError
		if errors.As(err, &limitErr) {
			err = fmt.Errorf("response %w", err)
		}
		return err
	}
	if asset != "" {
		var digest [sha256.Size]byte
		copy(digest[:], h.Sum(nil))
		if err = VerifyRemoteDigest(asset, digest); err != nil {
			return err
		}
	}
	if validator != nil {
		if err = validator(tmpPath); err != nil {
			return err
		}
	}
	if err = os.Chmod(tmpPath, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func validateGeoDataFile(asset AssetType, path string) error {
	if asset == AssetMMDB || asset == AssetASN {
		if !mmdb.Verify(path) {
			return fmt.Errorf("invalid %s database", asset)
		}
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	loader, err := GetGeoDataLoader("standard")
	if err != nil {
		return err
	}
	if asset == AssetGeoIP {
		_, err = loader.LoadIPByBytes(data, "cn")
	} else {
		_, err = loader.LoadSiteByBytes(data, "cn")
	}
	return err
}

func verifyExistingAsset(asset AssetType, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return VerifyRemoteAsset(asset, data)
}

func InitGeoSite() error {
	geoSiteEnable.Store(true)
	initGeoSiteMutex.Lock()
	defer initGeoSiteMutex.Unlock()
	if _, err := os.Stat(C.Path.GeoSite()); os.IsNotExist(err) {
		log.Infoln("Can't find GeoSite.dat, start download")
		if err := downloadToPath(AssetGeoSite, GeoSiteUrl(), C.Path.GeoSite(), func(path string) error { return validateGeoDataFile(AssetGeoSite, path) }); err != nil {
			return fmt.Errorf("can't download GeoSite.dat: %s", err.Error())
		}
		log.Infoln("Download GeoSite.dat finish")
		initGeoSite = false
	}
	if !initGeoSite {
		authErr := verifyExistingAsset(AssetGeoSite, C.Path.GeoSite())
		if err := Verify(C.GeositeName); err != nil || authErr != nil {
			log.Warnln("GeoSite.dat is invalid or unauthenticated, download replacement: %s", errors.Join(err, authErr))
			if err := downloadToPath(AssetGeoSite, GeoSiteUrl(), C.Path.GeoSite(), func(path string) error { return validateGeoDataFile(AssetGeoSite, path) }); err != nil {
				return fmt.Errorf("can't download GeoSite.dat: %s", err.Error())
			}
		}
		initGeoSite = true
	}
	return nil
}

func InitGeoIP() error {
	geoIpEnable.Store(true)
	initGeoIPMutex.Lock()
	defer initGeoIPMutex.Unlock()
	if GeodataMode() {
		if _, err := os.Stat(C.Path.GeoIP()); os.IsNotExist(err) {
			log.Infoln("Can't find GeoIP.dat, start download")
			if err := downloadToPath(AssetGeoIP, GeoIpUrl(), C.Path.GeoIP(), func(path string) error { return validateGeoDataFile(AssetGeoIP, path) }); err != nil {
				return fmt.Errorf("can't download GeoIP.dat: %s", err.Error())
			}
			log.Infoln("Download GeoIP.dat finish")
			initGeoIP = 0
		}

		if initGeoIP != 1 {
			authErr := verifyExistingAsset(AssetGeoIP, C.Path.GeoIP())
			if err := Verify(C.GeoipName); err != nil || authErr != nil {
				log.Warnln("GeoIP.dat is invalid or unauthenticated, download replacement: %s", errors.Join(err, authErr))
				if err := downloadToPath(AssetGeoIP, GeoIpUrl(), C.Path.GeoIP(), func(path string) error { return validateGeoDataFile(AssetGeoIP, path) }); err != nil {
					return fmt.Errorf("can't download GeoIP.dat: %s", err.Error())
				}
			}
			initGeoIP = 1
		}
		return nil
	}

	if _, err := os.Stat(C.Path.MMDB()); os.IsNotExist(err) {
		log.Infoln("Can't find MMDB, start download")
		if err := downloadToPath(AssetMMDB, MmdbUrl(), C.Path.MMDB(), func(path string) error { return validateGeoDataFile(AssetMMDB, path) }); err != nil {
			return fmt.Errorf("can't download MMDB: %s", err.Error())
		}
	}

	if initGeoIP != 2 {
		if !mmdb.Verify(C.Path.MMDB()) || verifyExistingAsset(AssetMMDB, C.Path.MMDB()) != nil {
			log.Warnln("MMDB invalid, download authenticated replacement")
			if err := downloadToPath(AssetMMDB, MmdbUrl(), C.Path.MMDB(), func(path string) error { return validateGeoDataFile(AssetMMDB, path) }); err != nil {
				return fmt.Errorf("can't download MMDB: %s", err.Error())
			}
		}
		initGeoIP = 2
	}
	return nil
}

func InitASN() error {
	asnEnable.Store(true)
	initASNMutex.Lock()
	defer initASNMutex.Unlock()
	if _, err := os.Stat(C.Path.ASN()); os.IsNotExist(err) {
		log.Infoln("Can't find ASN.mmdb, start download")
		if err := downloadToPath(AssetASN, ASNUrl(), C.Path.ASN(), func(path string) error { return validateGeoDataFile(AssetASN, path) }); err != nil {
			return fmt.Errorf("can't download ASN.mmdb: %s", err.Error())
		}
		log.Infoln("Download ASN.mmdb finish")
		initASN = false
	}
	if !initASN {
		if !mmdb.Verify(C.Path.ASN()) || verifyExistingAsset(AssetASN, C.Path.ASN()) != nil {
			log.Warnln("ASN invalid, download authenticated replacement")
			if err := downloadToPath(AssetASN, ASNUrl(), C.Path.ASN(), func(path string) error { return validateGeoDataFile(AssetASN, path) }); err != nil {
				return fmt.Errorf("can't download ASN: %s", err.Error())
			}
		}
		initASN = true
	}
	return nil
}

func GeoIpEnable() bool {
	return geoIpEnable.Load()
}

func GeoSiteEnable() bool {
	return geoSiteEnable.Load()
}

func ASNEnable() bool {
	return asnEnable.Load()
}
