package reality

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		Dest:        "example.com:443",
		PrivateKey:  base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		ShortID:     []string{"0123456789abcdef"},
		ServerNames: []string{"example.com"},
	}
}

func TestConfigBuild(t *testing.T) {
	config := testConfig()
	config.MaxTimeDifference = 60000
	config.Mldsa65Seed = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	config.RequireX25519MLKEM768 = true
	config.MinClientVer = "25.9.11"
	config.MaxClientVer = "26.10"
	builder, err := config.Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	realityConfig := builder.realityConfig
	if realityConfig.MaxTimeDiff != time.Minute {
		t.Errorf("max-time-difference 60000 is %v, not Xray's 60000 milliseconds", realityConfig.MaxTimeDiff)
	}
	if !bytes.Equal(realityConfig.Mldsa65Seed, bytes.Repeat([]byte{2}, 32)) {
		t.Errorf("unexpected mldsa65 seed %x", realityConfig.Mldsa65Seed)
	}
	if !realityConfig.RequireX25519MLKEM768 {
		t.Error("require-x25519mlkem768 is lost")
	}
	if !bytes.Equal(realityConfig.MinClientVer, []byte{25, 9, 11}) || !bytes.Equal(realityConfig.MaxClientVer, []byte{26, 10, 0}) {
		t.Errorf("unexpected client versions %v %v", realityConfig.MinClientVer, realityConfig.MaxClientVer)
	}

	builder, err = testConfig().Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	realityConfig = builder.realityConfig
	if realityConfig.MaxTimeDiff != 0 || realityConfig.Mldsa65Seed != nil || realityConfig.RequireX25519MLKEM768 ||
		realityConfig.MinClientVer != nil || realityConfig.MaxClientVer != nil {
		t.Error("unexpected defaults")
	}
}

func TestConfigBuildInvalid(t *testing.T) {
	for name, modify := range map[string]func(*Config){
		"short seed":            func(c *Config) { c.Mldsa65Seed = base64.RawURLEncoding.EncodeToString(make([]byte, 31)) },
		"padded seed":           func(c *Config) { c.Mldsa65Seed = base64.URLEncoding.EncodeToString(make([]byte, 32)) },
		"seed is private key":   func(c *Config) { c.Mldsa65Seed = c.PrivateKey },
		"min-client-ver range":  func(c *Config) { c.MinClientVer = "26.256.0" },
		"min-client-ver parts":  func(c *Config) { c.MinClientVer = "1.2.3.4" },
		"max-client-ver letter": func(c *Config) { c.MaxClientVer = "26.x" },
	} {
		t.Run(name, func(t *testing.T) {
			config := testConfig()
			modify(&config)
			if _, err := config.Build(nil); err == nil {
				t.Error("accepted")
			}
		})
	}
}
