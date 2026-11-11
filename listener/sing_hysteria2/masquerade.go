package sing_hysteria2

import (
	"context"
	"net"
	"net/url"
	"time"

	"github.com/metacubex/mihomo/component/ca"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httputil"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/tls"
)

// newMasqueradeHandler builds the handler for the masquerade URL. An https
// upstream is verified against the system/custom CA pool unless
// skipCertVerify is set explicitly (masquerade-skip-cert-verify).
func newMasqueradeHandler(masquerade string, skipCertVerify bool, dialContext func(ctx context.Context, network, address string) (net.Conn, error)) (http.Handler, error) {
	if masquerade == "" {
		return nil, nil
	}
	masqueradeURL, err := url.Parse(masquerade)
	if err != nil {
		return nil, E.Cause(err, "parse masquerade URL")
	}
	switch masqueradeURL.Scheme {
	case "file":
		return http.FileServer(http.Dir(masqueradeURL.Path)), nil
	case "http", "https":
		tlsConfig, err := ca.GetTLSConfig(ca.Option{
			TLSConfig: &tls.Config{
				InsecureSkipVerify: skipCertVerify,
			},
		})
		if err != nil {
			return nil, err
		}
		return &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(masqueradeURL)
				r.Out.Host = masqueradeURL.Host
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				w.WriteHeader(http.StatusBadGateway)
			},
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
				// from http.DefaultTransport
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				DialContext:           dialContext,
			},
		}, nil
	default:
		return nil, E.New("unknown masquerade URL scheme: ", masqueradeURL.Scheme)
	}
}
