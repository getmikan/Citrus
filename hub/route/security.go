package route

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

// The limits of every controller listener. A client that trickles its request
// headers (or its TLS handshake, which shares ReadHeaderTimeout) is cut off
// before authentication can run; an idle keep-alive connection is closed.
// There is no ReadTimeout or WriteTimeout: the streams (/logs, /traffic,
// /connections, /events) are long-lived by design.
const (
	controllerReadHeaderTimeout = 10 * time.Second
	controllerIdleTimeout       = 2 * time.Minute
	controllerMaxHeaderBytes    = 256 << 10
)

func newServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: controllerReadHeaderTimeout,
		IdleTimeout:       controllerIdleTimeout,
		MaxHeaderBytes:    controllerMaxHeaderBytes,
	}
}

func serve(server *http.Server, l net.Listener, format string) {
	if err := server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Errorln(format, err)
	}
}

// isLoopbackAddr reports whether a listen address (host:port) only accepts
// connections from this host. An empty host (":9090") listens on every
// interface.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.WithZone("").IsLoopback()
}

func (c *Config) insecureError(key, addr string) error {
	return fmt.Errorf("%s %s is not a loopback address and secret is empty, so anyone who reaches it gets the whole controller API; "+
		"set secret, listen on a loopback address or external-controller-unix, or set external-controller-allow-insecure: true to accept this", key, addr)
}

// checkTCP refuses the plain tcp listener on a non-loopback address without a
// secret.
func (c *Config) checkTCP() error {
	if c.Addr == "" || c.Secret != "" || c.AllowInsecure || isLoopbackAddr(c.Addr) {
		return nil
	}
	return c.insecureError("external-controller", c.Addr)
}

// checkTLS refuses the tls listener on a non-loopback address without a
// secret, unless it requires and verifies client certificates: then the
// certificate is the credential.
func (c *Config) checkTLS() error {
	if c.TLSAddr == "" || c.Secret != "" || c.AllowInsecure || isLoopbackAddr(c.TLSAddr) {
		return nil
	}
	clientAuth := ca.ClientAuthTypeFromString(c.ClientAuthType)
	if clientAuth == tls.RequireAndVerifyClientCert || (clientAuth == tls.NoClientCert && c.ClientAuthCert != "") {
		return nil
	}
	return c.insecureError("external-controller-tls", c.TLSAddr)
}

// Validate reports the listeners that ReCreateServer would refuse to start.
func (c *Config) Validate() error {
	return errors.Join(c.checkTCP(), c.checkTLS())
}

// browserGuard protects a tcp or tls controller without a secret from web
// pages: with a wildcard CORS policy (the default) any site could otherwise
// read and change it through the browser of its user, and DNS rebinding gets
// around the same-origin policy. A request must name the controller by an IP
// address or localhost in its Host header, and a request with an Origin header
// (every cross-origin request, every websocket) must come from the controller
// itself or from an origin listed literally in allow-origins; the wildcard
// "*" does not count. Programs that are not browsers send no Origin header and
// are not affected. The DoH path, public by design, is left out.
func browserGuard(next http.Handler, allowOrigins []string, dohPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(dohPath) > 0 && dohPath[0] == '/' && strings.HasPrefix(r.URL.Path, dohPath) {
			next.ServeHTTP(w, r)
			return
		}
		if !isLocalHostHeader(r.Host) {
			render.Status(r, http.StatusForbidden)
			render.JSON(w, r, newError("controller without a secret: the Host header must be an IP address or localhost; set secret to use a host name"))
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !originAllowed(origin, r.Host, allowOrigins) {
			render.Status(r, http.StatusForbidden)
			render.JSON(w, r, newError("controller without a secret: origin "+origin+" is not allowed; set secret or list the origin in external-controller-cors.allow-origins"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isLocalHostHeader(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	_, err := netip.ParseAddr(host)
	return err == nil
}

func originAllowed(origin, host string, allowOrigins []string) bool {
	for _, allowed := range allowOrigins {
		if allowed != "*" && strings.EqualFold(strings.TrimSuffix(allowed, "/"), origin) {
			return true
		}
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return strings.EqualFold(u.Host, host)
}

// The hijacked websocket connections of the stream endpoints. The server does
// not track a hijacked connection, so http.Server.Close leaves it open; they
// are closed here when the controller configuration changes, so a stream
// authorized by a retired secret does not outlive it.
var (
	streamsMu sync.Mutex
	streams   = map[net.Conn]struct{}{}
)

func trackStream(c net.Conn) {
	streamsMu.Lock()
	streams[c] = struct{}{}
	streamsMu.Unlock()
}

// untrackStream closes a websocket connection when its handler is done.
func untrackStream(c net.Conn) {
	streamsMu.Lock()
	delete(streams, c)
	streamsMu.Unlock()
	_ = c.Close()
}

func closeStreams() {
	streamsMu.Lock()
	defer streamsMu.Unlock()
	for c := range streams {
		_ = c.Close()
		delete(streams, c)
	}
}
