package main

import "testing"

func TestAssetPlatform(t *testing.T) {
	const version = "v1.0.0-beta.2"
	// Asset names as build.yml produces them: citrus-<goos>-<output>-<version>.
	for name, want := range map[string][2]string{
		"citrus-linux-386-" + version + ".gz":              {"linux", "386"},
		"citrus-linux-386-softfloat-" + version + ".gz":    {"linux", "386"},
		"citrus-linux-amd64-v3-" + version + ".gz":         {"linux", "amd64"},
		"citrus-linux-amd64-compatible-" + version + ".gz": {"linux", "amd64"},
		"citrus-linux-arm64-" + version + ".gz":            {"linux", "arm64"},
		"citrus-linux-armv5-" + version + ".gz":            {"linux", "arm"},
		"citrus-linux-armv6-" + version + ".gz":            {"linux", "arm"},
		"citrus-linux-armv7-" + version + ".gz":            {"linux", "arm"},
		"citrus-linux-mips-hardfloat-" + version + ".gz":   {"linux", "mips"},
		"citrus-linux-mipsle-softfloat-" + version + ".gz": {"linux", "mipsle"},
		"citrus-linux-mips64le-" + version + ".gz":         {"linux", "mips64le"},
		"citrus-linux-loong64-abi1-" + version + ".gz":     {"linux", "loong64"},
		"citrus-linux-loong64-abi2-" + version + ".gz":     {"linux", "loong64"},
		"citrus-linux-riscv64-" + version + ".gz":          {"linux", "riscv64"},
		"citrus-darwin-arm64-" + version + ".gz":           {"darwin", "arm64"},
		"citrus-windows-amd64-v3-" + version + ".zip":      {"windows", "amd64"},
		"citrus-windows-arm64-" + version + ".zip":         {"windows", "arm64"},
		"citrus-freebsd-amd64-v1-" + version + ".gz":       {"freebsd", "amd64"},
		"citrus-android-armv7-" + version + ".gz":          {"android", "arm"},
		"citrus-android-arm64-v8-" + version + ".gz":       {"android", "arm64"},
	} {
		goos, goarch, ok := assetPlatform(name, version)
		if !ok || goos != want[0] || goarch != want[1] {
			t.Errorf("%s: got %s/%s ok=%v, want %s/%s", name, goos, goarch, ok, want[0], want[1])
		}
	}
	if _, _, ok := assetPlatform("citrus-"+version+".gz", version); ok {
		t.Error("a name without a platform was accepted")
	}
}
