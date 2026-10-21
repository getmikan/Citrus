// Package fallback is the page an inbound that speaks HTTP (WebSocket, gRPC, XHTTP) gives a
// request that is not its own (fallback-page), instead of a bare 404: whoever opens the
// server's address or a name it serves in a browser sees a small site of one page.
package fallback

import (
	"fmt"
	"os"

	"github.com/metacubex/http"
)

// MaxPage bounds the page: it is read once, when the listener starts, and held in memory.
const MaxPage = 1 << 20

// Page answers with file, an HTML page: the page at "/" (and /index.html) to GET and HEAD, a
// plain 404 to anything else, as a site of one page does.
func Page(file string) (http.Handler, error) {
	page, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("fallback-page: %w", err)
	}
	if len(page) > MaxPage {
		return nil, fmt.Errorf("fallback-page: %s is larger than %d bytes", file, MaxPage)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" || r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(page)
		}
	}), nil
}
