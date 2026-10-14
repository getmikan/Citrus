package memconservative

import (
	"fmt"
	"os"
	"strings"

	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"google.golang.org/protobuf/proto"
)

type GeoIPCache map[string]*router.GeoIP

func (g GeoIPCache) Has(key string) bool {
	return !(g.Get(key) == nil)
}

func (g GeoIPCache) Get(key string) *router.GeoIP {
	if g == nil {
		return nil
	}
	return g[key]
}

func (g GeoIPCache) Set(key string, value *router.GeoIP) {
	if g == nil {
		g = make(map[string]*router.GeoIP)
	}
	g[key] = value
}

func (g GeoIPCache) Unmarshal(filename, code string) (*router.GeoIP, error) {
	asset := C.Path.GetAssetLocation(filename)
	idx := strings.ToLower(asset + ":" + code)
	if g.Has(idx) {
		return g.Get(idx), nil
	}

	geoipBytes, err := Decode(asset, code)
	switch err {
	case nil:
		var geoip router.GeoIP
		if err := proto.Unmarshal(geoipBytes, &geoip); err != nil {
			return nil, err
		}
		g.Set(idx, &geoip)
		return &geoip, nil

	case errCodeNotFound:
		return nil, fmt.Errorf("country code %s%s%s", code, " not found in ", filename)

	// A record laid out differently (errInvalidGeodataFile) may still be
	// valid protobuf, so it gets a full parse. A varint or length that no
	// valid file can contain does not: reading the whole file again would
	// only spend more memory on the same corrupt data.
	case errFailedToReadBytes, errFailedToReadExpectedLenBytes, errInvalidGeodataFile:
		log.Warnln("failed to decode geoip file: %s%s", filename, ", fallback to the original ReadFile method")
		geoipBytes, err = os.ReadFile(asset)
		if err != nil {
			return nil, err
		}
		var geoipList router.GeoIPList
		if err := proto.Unmarshal(geoipBytes, &geoipList); err != nil {
			return nil, err
		}
		for _, geoip := range geoipList.GetEntry() {
			if strings.EqualFold(code, geoip.GetCountryCode()) {
				g.Set(idx, geoip)
				return geoip, nil
			}
		}

	default:
		return nil, err
	}

	return nil, fmt.Errorf("country code %s%s%s", code, " not found in ", filename)
}

type GeoSiteCache map[string]*router.GeoSite

func (g GeoSiteCache) Has(key string) bool {
	return !(g.Get(key) == nil)
}

func (g GeoSiteCache) Get(key string) *router.GeoSite {
	if g == nil {
		return nil
	}
	return g[key]
}

func (g GeoSiteCache) Set(key string, value *router.GeoSite) {
	if g == nil {
		g = make(map[string]*router.GeoSite)
	}
	g[key] = value
}

func (g GeoSiteCache) Unmarshal(filename, code string) (*router.GeoSite, error) {
	asset := C.Path.GetAssetLocation(filename)
	idx := strings.ToLower(asset + ":" + code)
	if g.Has(idx) {
		return g.Get(idx), nil
	}

	geositeBytes, err := Decode(asset, code)
	switch err {
	case nil:
		var geosite router.GeoSite
		if err := proto.Unmarshal(geositeBytes, &geosite); err != nil {
			return nil, err
		}
		g.Set(idx, &geosite)
		return &geosite, nil

	case errCodeNotFound:
		return nil, fmt.Errorf("list %s%s%s", code, " not found in ", filename)

	// A record laid out differently (errInvalidGeodataFile) may still be
	// valid protobuf, so it gets a full parse. A varint or length that no
	// valid file can contain does not: reading the whole file again would
	// only spend more memory on the same corrupt data.
	case errFailedToReadBytes, errFailedToReadExpectedLenBytes, errInvalidGeodataFile:
		log.Warnln("failed to decode geosite file: %s%s", filename, ", fallback to the original ReadFile method")
		geositeBytes, err = os.ReadFile(asset)
		if err != nil {
			return nil, err
		}
		var geositeList router.GeoSiteList
		if err := proto.Unmarshal(geositeBytes, &geositeList); err != nil {
			return nil, err
		}
		for _, geosite := range geositeList.GetEntry() {
			if strings.EqualFold(code, geosite.GetCountryCode()) {
				g.Set(idx, geosite)
				return geosite, nil
			}
		}

	default:
		return nil, err
	}

	return nil, fmt.Errorf("list %s%s%s", code, " not found in ", filename)
}
