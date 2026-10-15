package route

import (
	"compress/gzip"
	"strings"

	"github.com/metacubex/mihomo/hub/metrics"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// getMetrics serves the Prometheus metrics (`metrics.enable`); it is behind the
// controller secret like every other route (Prometheus: authorization with
// the bearer credentials).
func getMetrics(w http.ResponseWriter, r *http.Request) {
	o := metrics.Current()
	if !o.Enable {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, newError("metrics are disabled, set metrics.enable"))
		return
	}
	w.Header().Set("Content-Type", metrics.ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Add("Vary", "Accept-Encoding")
	// Prometheus asks for gzip; with the per-user series a scrape of 10k
	// users is ~3 MB of text and ~200 KB compressed.
	if acceptsGzip(r.Header.Get("Accept-Encoding")) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		gz, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
		_ = metrics.Write(gz, o)
		_ = gz.Close()
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = metrics.Write(w, o)
}

func acceptsGzip(header string) bool {
	for _, part := range strings.Split(header, ",") {
		coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if strings.EqualFold(strings.TrimSpace(coding), "gzip") {
			return strings.ReplaceAll(strings.TrimSpace(params), " ", "") != "q=0"
		}
	}
	return false
}

// healthAuth requires the secret on the health probes unless
// `health-without-auth` is set. The option is read on every request, so a
// reload of the configuration applies it without restarting the controller.
func healthAuth(secret string, next http.HandlerFunc) http.HandlerFunc {
	if secret == "" {
		return next
	}
	authenticated := authentication(secret)(next)
	return func(w http.ResponseWriter, r *http.Request) {
		if metrics.Current().HealthWithoutAuth {
			next(w, r)
			return
		}
		authenticated.ServeHTTP(w, r)
	}
}

// probe answers a health probe: 200 "ok", or 503 with the reason. The body
// carries nothing but the state, so it is safe to serve without the secret.
func probe(check func() (bool, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		ok, reason := check()
		if !ok {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(reason + "\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}
}
