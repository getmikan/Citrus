package route

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/metacubex/mihomo/component/profile/cachefile"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// maxStoragePayload is the largest value accepted by PUT /storage/{key}.
const maxStoragePayload = 1024 * 1024

func storageRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/{key}", getStorage)
	r.Put("/{key}", setStorage)
	r.Delete("/{key}", deleteStorage)
	return r
}

func getStorage(w http.ResponseWriter, r *http.Request) {
	key := getEscapeParam(r, "key")
	data := cachefile.Cache().GetStorage(key)
	w.Header().Set("Content-Type", "application/json")
	if len(data) == 0 {
		w.Write([]byte("null"))
		return
	}
	w.Write(data)
}

func setStorage(w http.ResponseWriter, r *http.Request) {
	key := getEscapeParam(r, "key")
	data, ok := readLimitedBody(w, r, maxStoragePayload)
	if !ok {
		return
	}
	if !json.Valid(data) {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	cachefile.Cache().SetStorage(key, data)
	render.NoContent(w, r)
}

func deleteStorage(w http.ResponseWriter, r *http.Request) {
	key := getEscapeParam(r, "key")
	cachefile.Cache().DeleteStorage(key)
	render.NoContent(w, r)
}

// readLimitedBody reads the request body, stopping at limit bytes instead of
// buffering a body of any size. On failure it writes the error response
// (413 over the limit, 400 otherwise) and returns false.
func readLimitedBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			render.Status(r, http.StatusRequestEntityTooLarge)
			render.JSON(w, r, newError(fmt.Sprintf("payload exceeds %dMB limit", limit>>20)))
			return nil, false
		}
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return nil, false
	}
	return data, true
}
