package sing_hysteria2

import (
	"context"
	"net"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMasqueradeHTTPSVerify(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("upstream"))
	}))
	defer upstream.Close()

	var dialer net.Dialer
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	}

	serve := func(skipCertVerify bool) *httptest.ResponseRecorder {
		handler, err := newMasqueradeHandler(upstream.URL, skipCertVerify, dial)
		require.NoError(t, err)
		require.NotNil(t, handler)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://example.com/", nil))
		return rec
	}

	t.Run("verify by default", func(t *testing.T) {
		rec := serve(false)
		assert.Equal(t, http.StatusBadGateway, rec.Code)
	})
	t.Run("explicit skip", func(t *testing.T) {
		rec := serve(true)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "upstream", rec.Body.String())
	})
}

func TestMasqueradeEmptyAndUnknownScheme(t *testing.T) {
	handler, err := newMasqueradeHandler("", false, nil)
	assert.NoError(t, err)
	assert.Nil(t, handler)

	_, err = newMasqueradeHandler("ftp://127.0.0.1/", false, nil)
	assert.Error(t, err)
}

func TestMasqueradeBindsHostToConfiguredBackend(t *testing.T) {
	host := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host <- r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	var dialer net.Dialer
	handler, err := newMasqueradeHandler(upstream.URL, false, dialer.DialContext)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "https://attacker.example/", nil)
	req.Host = "sibling.internal"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code)
	require.NotEqual(t, "sibling.internal", <-host)
}
