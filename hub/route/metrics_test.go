package route

import (
	"compress/gzip"
	"io"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/hub/metrics"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func get(h http.Handler, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func restoreTunnelStatus(t *testing.T) {
	prev := tunnel.Status()
	t.Cleanup(func() {
		switch prev {
		case tunnel.Running:
			tunnel.OnRunning()
		case tunnel.Inner:
			tunnel.OnInnerLoading()
		default:
			tunnel.OnSuspend()
		}
	})
}

func TestMetricsRoute(t *testing.T) {
	t.Cleanup(func() { metrics.SetOptions(metrics.Options{}) })
	h := router(false, testSecret, "", Cors{})

	metrics.SetOptions(metrics.Options{})
	assert.Equal(t, http.StatusUnauthorized, get(h, "/metrics", "").Code)
	assert.Equal(t, http.StatusNotFound, get(h, "/metrics", testSecret).Code, "disabled")

	metrics.SetOptions(metrics.Options{Enable: true})
	assert.Equal(t, http.StatusUnauthorized, get(h, "/metrics", "").Code)
	assert.Equal(t, http.StatusUnauthorized, get(h, "/metrics", "wrong").Code)
	rec := get(h, "/metrics", testSecret)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, metrics.ContentType, rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "# TYPE citrus_traffic_bytes_total counter\n")
	assert.NotContains(t, rec.Body.String(), "citrus_user_")

	// gzip when asked for
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+testSecret)
	req.Header.Set("Accept-Encoding", "gzip")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "gzip", rec.Header().Get("Content-Encoding"))
	gz, err := gzip.NewReader(rec.Body)
	require.NoError(t, err)
	body, err := io.ReadAll(gz)
	require.NoError(t, err)
	assert.Contains(t, string(body), "# TYPE citrus_traffic_bytes_total counter\n")
	assert.False(t, acceptsGzip("gzip;q=0"))
	assert.True(t, acceptsGzip("deflate, GZIP;q=0.5"))

	// health-without-auth does not open /metrics
	metrics.SetOptions(metrics.Options{Enable: true, HealthWithoutAuth: true})
	assert.Equal(t, http.StatusUnauthorized, get(h, "/metrics", "").Code)
}

func TestHealthProbes(t *testing.T) {
	restoreTunnelStatus(t)
	t.Cleanup(func() { metrics.SetOptions(metrics.Options{}) })
	h := router(false, testSecret, "", Cors{})

	tunnel.OnRunning()
	metrics.SetOptions(metrics.Options{})
	for _, path := range []string{"/healthz", "/readyz"} {
		assert.Equal(t, http.StatusUnauthorized, get(h, path, "").Code, "%s requires the secret by default", path)
		rec := get(h, path, testSecret)
		assert.Equal(t, http.StatusOK, rec.Code, path)
		assert.Equal(t, "ok\n", rec.Body.String())
	}

	metrics.SetOptions(metrics.Options{HealthWithoutAuth: true})
	for _, path := range []string{"/healthz", "/readyz"} {
		assert.Equal(t, http.StatusOK, get(h, path, "").Code, path)
	}
	// the rest of the API is still protected
	assert.Equal(t, http.StatusUnauthorized, get(h, "/", "").Code)

	tunnel.OnSuspend()
	rec := get(h, "/healthz", "")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "suspend", strings.TrimSpace(rec.Body.String()))
	assert.Equal(t, http.StatusServiceUnavailable, get(h, "/readyz", "").Code)

	tunnel.OnInnerLoading()
	assert.Equal(t, http.StatusServiceUnavailable, get(h, "/healthz", "").Code)
	assert.Equal(t, http.StatusServiceUnavailable, get(h, "/readyz", "").Code)

	tunnel.OnRunning()
	assert.Equal(t, http.StatusOK, get(h, "/healthz", "").Code)
	assert.Equal(t, http.StatusOK, get(h, "/readyz", "").Code)

	// without a secret the probes are open whatever the option
	metrics.SetOptions(metrics.Options{})
	assert.Equal(t, http.StatusOK, get(router(false, "", "", Cors{}), "/healthz", "").Code)
}
