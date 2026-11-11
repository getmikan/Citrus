package config

import (
	"strings"
	"testing"
)

func TestParseGeneralValidatesGeodataPins(t *testing.T) {
	for _, pin := range []string{"short", strings.Repeat("z", 64), strings.Repeat("0", 62)} {
		cfg := DefaultRawConfig()
		cfg.GeoXSHA256.GeoIp = pin
		_, err := parseGeneral(cfg)
		if err == nil {
			t.Fatalf("invalid pin %q accepted", pin)
		}
	}
	pin := strings.Repeat("A", 64)
	cfg := DefaultRawConfig()
	cfg.GeoXSHA256.GeoIp = pin
	general, err := parseGeneral(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if general.GeoXSHA256.GeoIp != strings.ToLower(pin) {
		t.Fatalf("geodata policy lost: %+v", general)
	}
}
