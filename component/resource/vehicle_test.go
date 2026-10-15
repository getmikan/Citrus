package resource

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
)

// serveBytes streams size bytes without buffering them, so a test can push a
// body past DefaultSizeLimit cheaply.
func serveBytes(t *testing.T, size int64) *httptest.Server {
	t.Helper()
	chunk := make([]byte, 32*1024)
	for i := range chunk {
		chunk[i] = 'a'
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		for left := size; left > 0; {
			n := int64(len(chunk))
			if left < n {
				n = left
			}
			if _, err := w.Write(chunk[:n]); err != nil {
				return
			}
			left -= n
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func readVehicle(t *testing.T, url string, sizeLimit int64) ([]byte, error) {
	t.Helper()
	v := NewHTTPVehicle(url, filepath.Join(t.TempDir(), "p.yaml"), "", nil, 10*time.Second, sizeLimit)
	buf, _, err := v.Read(context.Background(), utils.HashType{})
	return buf, err
}

func TestHTTPVehicleExplicitSizeLimit(t *testing.T) {
	srv := serveBytes(t, 1024)

	// a body of exactly the limit is accepted
	buf, err := readVehicle(t, srv.URL, 1024)
	if err != nil || len(buf) != 1024 {
		t.Fatalf("exact limit: len=%d err=%v", len(buf), err)
	}

	// one byte over the limit is an error, not a truncated body
	buf, err = readVehicle(t, srv.URL, 1023)
	var limitErr *utils.SizeLimitError
	if !errors.As(err, &limitErr) || limitErr.Limit != 1023 {
		t.Fatalf("want SizeLimitError(1023), got %v", err)
	}
	if buf != nil {
		t.Fatalf("want no data on overflow, got %d bytes", len(buf))
	}
}

func TestHTTPVehicleDefaultSizeLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("streams DefaultSizeLimit bytes")
	}
	srv := serveBytes(t, DefaultSizeLimit+1)

	_, err := readVehicle(t, srv.URL, 0)
	var limitErr *utils.SizeLimitError
	if !errors.As(err, &limitErr) || limitErr.Limit != DefaultSizeLimit {
		t.Fatalf("size-limit 0 should use DefaultSizeLimit, got %v", err)
	}

	// size-limit -1 opts out of the cap
	buf, err := readVehicle(t, srv.URL, -1)
	if err != nil || int64(len(buf)) != DefaultSizeLimit+1 {
		t.Fatalf("size-limit -1: len=%d err=%v", len(buf), err)
	}
}
