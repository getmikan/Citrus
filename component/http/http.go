package http

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	URL "net/url"
	"runtime"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"

	"github.com/metacubex/http"
)

var (
	ua string
)

func UA() string {
	return ua
}

func SetUA(UA string) {
	ua = UA
}

func HttpRequest(ctx context.Context, url, method string, header map[string][]string, body io.Reader, options ...Option) (*http.Response, error) {
	opt := option{}
	for _, o := range options {
		o(&opt)
	}
	method = strings.ToUpper(method)
	urlRes, err := URL.Parse(url)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, urlRes.String(), body)
	if err != nil {
		return nil, err
	}

	for k, v := range header {
		for _, v := range v {
			req.Header.Add(k, v)
		}
	}

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UA())
	}

	if user := urlRes.User; user != nil {
		password, _ := user.Password()
		req.SetBasicAuth(user.Username(), password)
	}

	req = req.WithContext(ctx)

	tlsConfig, err := ca.GetTLSConfig(opt.caOption)
	if err != nil {
		return nil, err
	}

	policy := newRedirectPolicy(ctx, urlRes.Hostname())
	transport := &http.Transport{
		// from http.DefaultTransport
		DisableKeepAlives:     runtime.GOOS == "android",
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			approved, pinned, err := policy.approvedFor(network, address)
			if err != nil {
				return nil, err
			}
			if opt.dialer != nil {
				if pinned {
					return dialPinned(ctx, opt.dialer.DialContext, network, address, approved)
				}
				return opt.dialer.DialContext(ctx, network, address)
			}
			// A validated redirect target still enters the tunnel by name, so
			// domain rules match it and a proxy resolves it remotely; only
			// DIRECT is held to the validated address.
			var conn net.Conn
			if pinned {
				conn, err = inner.HandleTcpResolved(inner.GetTunnel(), address, approved[0], opt.specialProxy)
			} else {
				conn, err = inner.HandleTcp(inner.GetTunnel(), address, opt.specialProxy)
			}
			if err == nil {
				return conn, nil
			}
			if pinned {
				return dialPinned(ctx, func(ctx context.Context, network, address string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, address)
				}, network, address, approved)
			}
			return dialer.DialContext(ctx, network, address)
		},
		TLSClientConfig: tlsConfig,
	}

	client := http.Client{Transport: transport, CheckRedirect: policy.checkRedirect}
	return client.Do(req)
}

// dialPinned dials a validated redirect target by its validated addresses
// rather than by name, so a second DNS answer cannot redirect the connection.
func dialPinned(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), network, address string, approved []netip.Addr) (net.Conn, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, ip := range approved {
		conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

type Option func(opt *option)

type option struct {
	specialProxy string
	dialer       C.Dialer
	caOption     ca.Option
}

func WithSpecialProxy(name string) Option {
	return func(opt *option) {
		opt.specialProxy = name
	}
}

func WithDialer(dialer C.Dialer) Option {
	return func(opt *option) {
		opt.dialer = dialer
	}
}

func WithCAOption(caOption ca.Option) Option {
	return func(opt *option) {
		opt.caOption = caOption
	}
}
