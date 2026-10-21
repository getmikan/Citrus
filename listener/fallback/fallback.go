// Package fallback is the page an inbound that speaks HTTP (WebSocket, gRPC, XHTTP) gives a
// request that is not its own (fallback-page), instead of a bare 404: whoever opens the
// server's address or a name it serves in a browser sees a small site of one page.
package fallback

import (
	"fmt"
	"io"
	"os"
	"strings"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
)

// MaxPage bounds the page: it is read once, when the listener starts, and held in memory.
const MaxPage = 1 << 20

// Page answers with file, an HTML page under the safe paths (the home directory, or
// SAFE_PATHS) like the other files a config names: the page at "/" (and /index.html) to GET
// and HEAD, a plain 404 to anything else, as a site of one page does.
func Page(file string) (http.Handler, error) {
	file = C.Path.Resolve(file)
	if !C.Path.IsSafePath(file) {
		return nil, fmt.Errorf("fallback-page: %w", C.Path.ErrNotSafePath(file))
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("fallback-page: %w", err)
	}
	defer f.Close()
	page, err := io.ReadAll(io.LimitReader(f, MaxPage+1))
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

// WebSocket is the handler of an inbound's WebSocket path, ws, with page (nil: none) for
// the requests that are not its own: every other path, and the path itself when the request
// is no WebSocket upgrade (a browser opening it). Without a page it is the path alone, as
// before. A path of "/" takes the page into its own handler: ServeMux takes a pattern once.
func WebSocket(path string, page http.Handler, ws http.HandlerFunc) http.Handler {
	mux := http.NewServeMux()
	if page != nil && path != "/" {
		mux.Handle("/", page)
	}
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if page != nil && !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			page.ServeHTTP(w, r)
			return
		}
		ws(w, r)
	})
	return mux
}
