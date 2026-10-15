package xhttp

import (
	"io"
	"net"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXPaddingBytesZeroMeansDefault(t *testing.T) {
	for _, value := range []string{"", "0", "0-0"} {
		r, err := (&Config{XPaddingBytes: value}).GetNormalizedXPaddingBytes()
		require.NoError(t, err, value)
		assert.Equal(t, Range{100, 1000}, r, value)
	}

	r, err := (&Config{XPaddingBytes: "16-32"}).GetNormalizedXPaddingBytes()
	require.NoError(t, err)
	assert.Equal(t, Range{16, 32}, r)

	// a client with "0-0" pads its requests, so a server with "0-0" accepts them
	cfg := &Config{Path: "/xhttp", XPaddingBytes: "0-0"}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/xhttp/session", nil)
	require.NoError(t, cfg.FillStreamRequest(req, ""))
	assert.Contains(t, req.Header.Get("Referer"), "x_padding=")
}

func TestScRangesZeroMeansDefault(t *testing.T) {
	cfg := &Config{
		ScMaxEachPostBytes:   "0",
		ScMinPostsIntervalMs: "0-0",
		ScMaxBufferedPosts:   "0",
		ScStreamUpServerSecs: "0",
	}
	r, err := cfg.GetNormalizedScMaxEachPostBytes()
	require.NoError(t, err)
	assert.Equal(t, Range{1000000, 1000000}, r)
	r, err = cfg.GetNormalizedScMinPostsIntervalMs()
	require.NoError(t, err)
	assert.Equal(t, Range{30, 30}, r)
	r, err = cfg.GetNormalizedScMaxBufferedPosts()
	require.NoError(t, err)
	assert.Equal(t, Range{30, 30}, r)
	r, err = cfg.GetNormalizedScStreamUpServerSecs()
	require.NoError(t, err)
	assert.Equal(t, Range{20, 80}, r)

	_, err = (&Config{ScMaxEachPostBytes: "0-100"}).GetNormalizedScMaxEachPostBytes()
	assert.Error(t, err)
}

func TestPathWithQuery(t *testing.T) {
	testCases := []struct {
		path      string
		wantPath  string
		wantQuery string
	}{
		{"", "/", ""},
		{"/", "/", ""},
		{"xhttp", "/xhttp/", ""},
		{"/xhttp?ed=2048", "/xhttp/", "ed=2048"},
		{"/xhttp/?a=b&c=d", "/xhttp/", "a=b&c=d"},
		{"?a=b", "/", "a=b"},
		{"/xhttp?a=b?c", "/xhttp/", "a=b?c"},
	}
	for _, testCase := range testCases {
		cfg := &Config{Path: testCase.path}
		assert.Equal(t, testCase.wantPath, cfg.NormalizedPath(), testCase.path)
		assert.Equal(t, testCase.wantQuery, cfg.NormalizedQuery(), testCase.path)
	}

	// without a path placement the trailing slash is not forced
	cfg := &Config{Path: "/xhttp?a=b", SessionPlacement: PlacementHeader, SeqPlacement: PlacementHeader}
	assert.Equal(t, "/xhttp", cfg.NormalizedPath())
	assert.Equal(t, "a=b", cfg.NormalizedQuery())
}

func TestServerHandlerPathWithQuery(t *testing.T) {
	config := Config{
		Path: "/xhttp?ed=2048",
		Mode: "packet-up",
	}
	handler, err := NewServerHandler(ServerOption{
		Config: config,
		ConnHandler: func(conn net.Conn, r *http.Request) {
			_ = conn.Close()
		},
	})
	require.NoError(t, err)

	for _, target := range []string{
		"https://example.com/xhttp/session?ed=2048",
		"https://example.com/xhttp/session?other=1",
		"https://example.com/xhttp/session",
	} {
		req := httptest.NewRequest(http.MethodGet, target, io.NopCloser(http.NoBody))
		require.NoError(t, config.FillDownloadRequest(req, ""))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusOK, recorder.Result().StatusCode, target)
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com/other/session?ed=2048", io.NopCloser(http.NoBody))
	require.NoError(t, config.FillDownloadRequest(req, ""))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusNotFound, recorder.Result().StatusCode)
}

func TestDefaultReuseConfig(t *testing.T) {
	cfg := DefaultReuseConfig()
	concurrency, connections, err := cfg.ResolveManagerConfig()
	require.NoError(t, err)
	assert.Equal(t, Range{0, 0}, concurrency)
	assert.Equal(t, Range{3, 3}, connections)
	cMaxReuseTimes, hMaxRequestTimes, hMaxReusableSecs, err := cfg.ResolveEntryConfig()
	require.NoError(t, err)
	assert.Equal(t, Range{0, 0}, cMaxReuseTimes)
	assert.Equal(t, Range{600, 900}, hMaxRequestTimes)
	assert.Equal(t, Range{1800, 3000}, hMaxReusableSecs)
}
