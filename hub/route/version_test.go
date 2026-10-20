package route

import (
	"encoding/json"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"

	"github.com/stretchr/testify/require"
)

func TestVersionNamesTheCore(t *testing.T) {
	rec := httptest.NewRecorder()
	version(rec, httptest.NewRequest(http.MethodGet, "/version", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	// the fields of mihomo stay as they are
	require.Equal(t, true, body["meta"])
	require.Equal(t, C.Version, body["version"])
	require.Equal(t, "citrus", body["core"])
}
