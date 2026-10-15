package route

import (
	"strings"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
)

// endlessReader counts how much of an endless body the handler reads.
type endlessReader struct{ n int64 }

func (r *endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	r.n += int64(len(p))
	return len(p), nil
}

func TestSetStoragePayloadLimit(t *testing.T) {
	h := storageRouter()

	// a value just over the limit is refused with 413
	body := `"` + strings.Repeat("a", maxStoragePayload-1) + `"`
	req := httptest.NewRequest(http.MethodPut, "/key", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)

	// an endless body is not read much past the limit
	endless := &endlessReader{}
	req = httptest.NewRequest(http.MethodPut, "/key", endless)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.LessOrEqual(t, endless.n, int64(2*maxStoragePayload))

	// invalid JSON within the limit is still a bad request
	req = httptest.NewRequest(http.MethodPut, "/key", strings.NewReader("{"))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
