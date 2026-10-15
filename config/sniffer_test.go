package config

import (
	"testing"

	snifferTypes "github.com/metacubex/mihomo/constant/sniffer"

	"github.com/stretchr/testify/assert"
)

func TestParseBitTorrentSniffer(t *testing.T) {
	// sniffer names are matched case-insensitively against the type list
	for _, name := range []string{"BitTorrent", "bittorrent", "BITTORRENT"} {
		cfg, err := parseSniffer(RawSniffer{
			Enable: true,
			Sniff: map[string]RawSniffingConfig{
				name: {},
			},
		}, nil)
		assert.NoError(t, err, name)
		assert.Contains(t, cfg.Sniffers, snifferTypes.BitTorrent, name)
	}
}

// the port list docs/config.yaml spells out for the default range must parse
func TestParseBitTorrentSnifferDocumentedPorts(t *testing.T) {
	cfg, err := parseSniffer(RawSniffer{
		Enable: true,
		Sniff: map[string]RawSniffingConfig{
			"BitTorrent": {Ports: []string{"1-20", "24", "26-109", "111-118", "120-142", "144-586", "588-3305", "3307-5899", "5901-65535"}},
		},
	}, nil)
	assert.NoError(t, err)
	ports := cfg.Sniffers[snifferTypes.BitTorrent].Ports
	assert.True(t, ports.Check(6881))
	assert.True(t, ports.Check(24))
	assert.False(t, ports.Check(22))
	assert.False(t, ports.Check(3306))
}

func TestParseSnifferSkipThreshold(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte("sniffer:\n  enable: true\n"))
	assert.NoError(t, err)
	cfg, err := parseSniffer(raw.Sniffer, nil)
	assert.NoError(t, err)
	assert.Nil(t, cfg.SkipThreshold, "omitted keeps the dispatcher default")

	for _, v := range []int{-1, 0, 5, 254} {
		v := v
		cfg, err := parseSniffer(RawSniffer{Enable: true, SkipThreshold: &v}, nil)
		assert.NoError(t, err, v)
		assert.Equal(t, v, *cfg.SkipThreshold)
	}
	for _, v := range []int{-2, 255, 256, 1000} {
		v := v
		_, err := parseSniffer(RawSniffer{Enable: true, SkipThreshold: &v}, nil)
		assert.Error(t, err, v)
	}
}

func TestParseBitTorrentSnifferLegacyList(t *testing.T) {
	cfg, err := parseSniffer(RawSniffer{
		Enable:   true,
		Sniffing: []string{"BitTorrent"},
	}, nil)
	assert.NoError(t, err)
	assert.Contains(t, cfg.Sniffers, snifferTypes.BitTorrent)
}
