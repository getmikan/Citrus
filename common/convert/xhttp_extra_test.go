package convert_test

import (
	"net/url"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	. "github.com/metacubex/mihomo/common/convert"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func convertXHTTPExtra(t *testing.T, extra string) map[string]any {
	link := "vless://88888888-4444-4444-4444-121212121212@example.com:443?type=xhttp&security=tls&sni=example.com" +
		"&path=" + url.QueryEscape("/xhttp?ed=2048") + "&mode=packet-up&extra=" + url.QueryEscape(extra) + "#xhttp"
	proxies, err := ConvertsV2Ray([]byte(link))
	require.NoError(t, err)
	require.Len(t, proxies, 1)

	_, err = adapter.ParseProxy(proxies[0])
	require.NoError(t, err)

	opts, ok := proxies[0]["xhttp-opts"].(map[string]any)
	require.True(t, ok)
	return opts
}

func TestConvertsV2RayXHTTPExtraRangesAsNumbers(t *testing.T) {
	opts := convertXHTTPExtra(t, `{
		"xPaddingBytes": 500,
		"uplinkChunkSize": 4096,
		"scMaxEachPostBytes": 1000000,
		"scMinPostsIntervalMs": 30,
		"sessionIDLength": 24,
		"xmux": {"maxConcurrency": 16, "hMaxRequestTimes": 800, "hMaxReusableSecs": 2000, "hKeepAlivePeriod": 15}
	}`)

	assert.Equal(t, "/xhttp?ed=2048", opts["path"])
	assert.Equal(t, "500", opts["x-padding-bytes"])
	assert.Equal(t, "4096", opts["uplink-chunk-size"])
	assert.Equal(t, "1000000", opts["sc-max-each-post-bytes"])
	assert.Equal(t, "30", opts["sc-min-posts-interval-ms"])
	assert.Equal(t, "24", opts["session-length"])
	assert.Equal(t, map[string]any{
		"max-concurrency":     "16",
		"h-max-request-times": "800",
		"h-max-reusable-secs": "2000",
		"h-keep-alive-period": 15,
	}, opts["reuse-settings"])
}

func TestConvertsV2RayXHTTPExtraRangesAsStrings(t *testing.T) {
	opts := convertXHTTPExtra(t, `{
		"xPaddingBytes": "100-1000",
		"uplinkChunkSize": "2048-4096",
		"scMaxEachPostBytes": "500000-1000000",
		"scMinPostsIntervalMs": "10-50",
		"sessionIDLength": "16-32",
		"xmux": {"maxConnections": "2-4", "cMaxReuseTimes": "0", "hMaxRequestTimes": "600-900", "hMaxReusableSecs": "1800-3000"},
		"downloadSettings": {
			"address": "download.example.com",
			"port": 8443,
			"xhttpSettings": {
				"path": "/down",
				"xmux": {"maxConnections": 1},
				"extra": {"xmux": {"maxConcurrency": "8-16"}}
			}
		}
	}`)

	assert.Equal(t, "100-1000", opts["x-padding-bytes"])
	assert.Equal(t, "2048-4096", opts["uplink-chunk-size"])
	assert.Equal(t, "500000-1000000", opts["sc-max-each-post-bytes"])
	assert.Equal(t, "10-50", opts["sc-min-posts-interval-ms"])
	assert.Equal(t, "16-32", opts["session-length"])
	assert.Equal(t, map[string]any{
		"max-connections":     "2-4",
		"c-max-reuse-times":   "0",
		"h-max-request-times": "600-900",
		"h-max-reusable-secs": "1800-3000",
	}, opts["reuse-settings"])

	ds, ok := opts["download-settings"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "/down", ds["path"])
	assert.Equal(t, map[string]any{"max-concurrency": "8-16"}, ds["reuse-settings"]) // extra takes precedence
}
