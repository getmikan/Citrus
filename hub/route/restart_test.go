package route

import (
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
)

// A core whose configuration came from stdin cannot re-execute itself: the
// new process would read an empty stdin and exit.
func TestRestartRefusedWhenUnsupported(t *testing.T) {
	SetRestartUnsupported("config from stdin")
	t.Cleanup(func() { SetRestartUnsupported("") })

	for _, h := range []http.Handler{restartRouter(), upgradeRouter()} {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusConflict, rec.Code)
		assert.Contains(t, rec.Body.String(), "config from stdin")
	}
}
