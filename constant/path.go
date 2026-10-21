package constant

import (
	"fmt"
	"os"
	P "path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/constant/features"
)

const Name = "citrus"

var (
	GeositeName   = "GeoSite.dat"
	GeoipName     = "GeoIP.dat"
	ASNName       = "ASN.mmdb"
	BundleMRSName = "BundleMRS.7z"
)

// Path is used to get the configuration path
//
// on Unix systems, `$HOME/.config/citrus`.
// on Windows, `%USERPROFILE%/.config/citrus`.
var Path = func() *path {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir, _ = os.Getwd()
	}
	allowUnsafePath, _ := strconv.ParseBool(os.Getenv("SKIP_SAFE_PATH_CHECK"))
	homeDir = P.Join(homeDir, ".config", Name)

	if _, err = os.Stat(homeDir); err != nil {
		if configHome, ok := os.LookupEnv("XDG_CONFIG_HOME"); ok {
			homeDir = P.Join(configHome, Name)
		}
	}

	var safePaths []string
	for _, safePath := range filepath.SplitList(os.Getenv("SAFE_PATHS")) {
		safePath = strings.TrimSpace(safePath)
		if len(safePath) == 0 {
			continue
		}
		safePaths = append(safePaths, safePath)
	}

	return &path{homeDir: homeDir, configFile: "config.yaml", allowUnsafePath: allowUnsafePath, safePaths: safePaths}
}()

type path struct {
	homeDir         string
	configFile      string
	allowUnsafePath bool
	safePaths       []string
}

// SetHomeDir is used to set the configuration path
func SetHomeDir(root string) {
	Path.homeDir = root
}

// SetConfig is used to set the configuration file
func SetConfig(file string) {
	Path.configFile = file
}

func (p *path) HomeDir() string {
	return p.homeDir
}

func (p *path) Config() string {
	return p.configFile
}

// Resolve return a absolute path or a relative path with homedir
func (p *path) Resolve(path string) string {
	if !filepath.IsAbs(path) {
		return filepath.Join(p.HomeDir(), path)
	}
	return path
}

// IsSafePath return true if path is a subpath of homedir (or in the SAFE_PATHS environment variable)
//
// The check holds both for the path as written and for the path with every
// symlink (or Windows junction) in it resolved, so a link inside a safe
// directory cannot lead reads and writes outside of it. Safe directories may
// themselves be links; they are resolved too.
func (p *path) IsSafePath(path string) bool {
	if p.allowUnsafePath || features.CMFA {
		return true
	}
	path = p.Resolve(path)
	safePaths := p.SafePaths()
	if !underAny(path, safePaths) {
		return false
	}
	realPath, err := evalExisting(path)
	if err != nil {
		return false
	}
	realSafePaths := make([]string, 0, len(safePaths))
	for _, safePath := range safePaths {
		if realSafePath, err := evalExisting(safePath); err == nil {
			realSafePaths = append(realSafePaths, realSafePath)
		}
	}
	return underAny(realPath, realSafePaths)
}

func underAny(path string, roots []string) bool {
	for _, root := range roots {
		if rel, err := filepath.Rel(root, path); err == nil {
			if filepath.IsLocal(rel) {
				return true
			}
		}
	}
	return false
}

// evalExisting resolves the symlinks in the longest existing prefix of path
// and appends the part that does not exist yet. A dangling symlink is an
// error: writing through it would create its target, wherever that is.
func evalExisting(path string) (string, error) {
	path = filepath.Clean(path)
	real, err := filepath.EvalSymlinks(path)
	if err == nil {
		return real, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	if _, lerr := os.Lstat(path); lerr == nil {
		return "", fmt.Errorf("%s: dangling symlink", path)
	}
	dir, file := filepath.Split(path)
	dir = filepath.Clean(dir)
	if dir == path { // the root itself does not exist
		return "", err
	}
	realDir, err := evalExisting(dir)
	if err != nil {
		return "", err
	}
	return filepath.Join(realDir, file), nil
}

func (p *path) SafePaths() []string {
	return append([]string{p.homeDir}, p.safePaths...) // add homedir to safePaths
}

// HoldsCoreState reports whether dir is the home directory, the directory of
// the config file or a SAFE_PATHS root, or an ancestor of one of them: a
// directory the core keeps its own files in. Such a directory must never be
// emptied or served as a whole, whatever SKIP_SAFE_PATH_CHECK says.
func (p *path) HoldsCoreState(dir string) bool {
	dir = filepath.Clean(p.Resolve(dir))
	if realDir, err := evalExisting(dir); err == nil {
		dir = filepath.Clean(realDir)
	} else {
		// A path whose identity cannot be established must never be used as a
		// destructive/served UI root.
		return true
	}
	roots := append([]string{filepath.Dir(p.Resolve(p.configFile))}, p.SafePaths()...)
	for _, root := range roots {
		if root == "" {
			continue
		}
		root = filepath.Clean(root)
		if realRoot, err := evalExisting(root); err == nil {
			root = filepath.Clean(realRoot)
		}
		if rel, err := filepath.Rel(dir, root); err == nil && filepath.IsLocal(rel) {
			return true
		}
	}
	return false
}

func (p *path) ErrNotSafePath(path string) error {
	return ErrNotSafePath{Path: path, SafePaths: p.SafePaths()}
}

type ErrNotSafePath struct {
	Path      string
	SafePaths []string
}

func (e ErrNotSafePath) Error() string {
	return fmt.Sprintf("path is not subpath of home directory or SAFE_PATHS: %s \n allowed paths: %s", e.Path, e.SafePaths)
}

func (p *path) GetPathByHash(prefix, name string) string {
	hash := utils.MakeHash([]byte(name))
	filename := hash.String()
	return filepath.Join(p.HomeDir(), prefix, filename)
}

func (p *path) MMDB() string {
	files, err := os.ReadDir(p.homeDir)
	if err != nil {
		return ""
	}
	for _, fi := range files {
		if fi.IsDir() {
			// 目录则直接跳过
			continue
		} else {
			if strings.EqualFold(fi.Name(), "Country.mmdb") ||
				strings.EqualFold(fi.Name(), "geoip.db") ||
				strings.EqualFold(fi.Name(), "geoip.metadb") {
				GeoipName = fi.Name()
				return P.Join(p.homeDir, fi.Name())
			}
		}
	}
	return P.Join(p.homeDir, "geoip.metadb")
}

func (p *path) ASN() string {
	files, err := os.ReadDir(p.homeDir)
	if err != nil {
		return ""
	}
	for _, fi := range files {
		if fi.IsDir() {
			// 目录则直接跳过
			continue
		} else {
			if strings.EqualFold(fi.Name(), "ASN.mmdb") {
				ASNName = fi.Name()
				return P.Join(p.homeDir, fi.Name())
			}
		}
	}
	return P.Join(p.homeDir, ASNName)
}

func (p *path) BundleMRS() string {
	files, err := os.ReadDir(p.homeDir)
	if err != nil {
		return ""
	}
	for _, fi := range files {
		if fi.IsDir() {
			// 目录则直接跳过
			continue
		} else {
			if strings.EqualFold(fi.Name(), "BundleMRS.7z") {
				BundleMRSName = fi.Name()
				return P.Join(p.homeDir, fi.Name())
			}
		}
	}
	return P.Join(p.homeDir, BundleMRSName)
}

func (p *path) OldCache() string {
	return P.Join(p.homeDir, ".cache")
}

func (p *path) Cache() string {
	return P.Join(p.homeDir, "cache.db")
}

func (p *path) GeoIP() string {
	files, err := os.ReadDir(p.homeDir)
	if err != nil {
		return ""
	}
	for _, fi := range files {
		if fi.IsDir() {
			// 目录则直接跳过
			continue
		} else {
			if strings.EqualFold(fi.Name(), "GeoIP.dat") {
				GeoipName = fi.Name()
				return P.Join(p.homeDir, fi.Name())
			}
		}
	}
	return P.Join(p.homeDir, "GeoIP.dat")
}

func (p *path) GeoSite() string {
	files, err := os.ReadDir(p.homeDir)
	if err != nil {
		return ""
	}
	for _, fi := range files {
		if fi.IsDir() {
			// 目录则直接跳过
			continue
		} else {
			if strings.EqualFold(fi.Name(), "GeoSite.dat") {
				GeositeName = fi.Name()
				return P.Join(p.homeDir, fi.Name())
			}
		}
	}
	return P.Join(p.homeDir, "GeoSite.dat")
}

func (p *path) GetAssetLocation(file string) string {
	return P.Join(p.homeDir, file)
}

func (p *path) GetExecutableFullPath() string {
	exePath, err := os.Executable()
	if err != nil {
		return "citrus"
	}
	res, _ := filepath.EvalSymlinks(exePath)
	return res
}
