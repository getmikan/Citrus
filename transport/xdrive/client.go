// Adapted from XTLS/Xray-core at 92ccc939aaf4; SPDX-License-Identifier: MPL-2.0

package xdrive

import (
	"context"
	"github.com/metacubex/http"
	"io"
	"sync"
	"time"

	"github.com/metacubex/tls"
	"net"
)

var errStalled = newError("the request made no progress")

type serviceTransport struct {
	plain  http.RoundTripper
	secure http.RoundTripper
	stall  time.Duration
}

// RoundTrip ends a request that stands still for t.stall, with no answer that
// long after its body went out or no byte of either body, but not one that just
// runs long: a large object on a slow link takes minutes and is fine as long as
// its bytes move
func (t *serviceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	next := t.plain
	if r.URL.Scheme == "https" {
		next = t.secure
	}

	ctx, cancel := context.WithCancelCause(r.Context())
	timer := time.AfterFunc(t.stall, func() { cancel(errStalled) })
	alive := func() { timer.Reset(t.stall) }
	end := func() {
		timer.Stop()
		cancel(nil)
	}
	r = r.WithContext(ctx)
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = &progressBody{ReadCloser: r.Body, alive: alive}
	}
	// a body sent again by the transport itself, after a GOAWAY or on a reused
	// connection that failed, moves just the same
	if getBody := r.GetBody; getBody != nil {
		r.GetBody = func() (io.ReadCloser, error) {
			body, err := getBody()
			if err != nil || body == http.NoBody {
				return body, err
			}
			return &progressBody{ReadCloser: body, alive: alive}, nil
		}
	}

	resp, err := next.RoundTrip(r)
	if err != nil {
		err = stalled(ctx, err)
		end()
		return nil, err
	}
	alive()
	resp.Body = &progressBody{ReadCloser: resp.Body, alive: alive, end: end, ctx: ctx}
	return resp, nil
}

// stalled returns errStalled for an error that the stall gave, which http2 reports
// as a plain cancel
func stalled(ctx context.Context, err error) error {
	if context.Cause(ctx) == errStalled {
		return errStalled
	}
	return err
}

type progressBody struct {
	io.ReadCloser
	alive func()
	end   func()
	// ctx is that of the request, for the body of its response
	ctx context.Context
}

func (b *progressBody) Read(p []byte) (int, error) {
	// http2 reads a request body up to 512 KiB at a time and sends it all before
	// the next read, which on a slow link could look like no progress
	n, err := b.ReadCloser.Read(p[:min(len(p), 16<<10)])
	if n > 0 {
		b.alive()
	}
	if err != nil && err != io.EOF && b.ctx != nil {
		err = stalled(b.ctx, err)
	}
	return n, err
}

func (b *progressBody) Close() error {
	err := b.ReadCloser.Close()
	if b.end != nil {
		b.end()
	}
	return err
}

// NewHTTPClient uses the caller's dialer for storage HTTP requests. HTTPS is
// negotiated per API URL; TLS belongs to these requests, not the storage stream.
func NewHTTPClient(dial, dialTLS func(context.Context, string, string) (net.Conn, error)) *http.Client {
	if dial == nil {
		dial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	if dialTLS == nil {
		dialTLS = func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				raw.Close()
				return nil, err
			}
			conn := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}})
			handshakeCtx, cancel := context.WithTimeout(ctx, driveTimeout)
			defer cancel()
			if err := conn.HandshakeContext(handshakeCtx); err != nil {
				raw.Close()
				return nil, err
			}
			return conn, nil
		}
	}
	secure := func(maxConns int) *http.Transport {
		return &http.Transport{
			DialTLSContext: dialTLS, ForceAttemptHTTP2: true, IdleConnTimeout: 90 * time.Second,
			MaxIdleConns: 32, MaxIdleConnsPerHost: 32, MaxConnsPerHost: maxConns,
		}
	}
	return &http.Client{Transport: &serviceTransport{
		plain:  &http.Transport{DialContext: dial, IdleConnTimeout: 90 * time.Second, MaxIdleConns: 32, MaxIdleConnsPerHost: 32, MaxConnsPerHost: 32},
		secure: &secureTransport{h2: secure(1), h1: secure(32)}, stall: driveTimeout,
	}}
}

func defaultHTTPClient(c Config) *http.Client {
	if c.Fronting == "" {
		return NewHTTPClient(nil, nil)
	}
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, network, c.Fronting)
	}
	return NewHTTPClient(dial, nil)
}

func (t *serviceTransport) CloseIdleConnections() {
	for _, next := range []http.RoundTripper{t.plain, t.secure} {
		if closer, ok := next.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}
func (t *secureTransport) CloseIdleConnections() {
	for _, next := range []http.RoundTripper{t.h2, t.h1} {
		if closer, ok := next.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}

// secureTransport keeps a host to one connection, all that h2 needs, as without
// a limit parallel requests would each dial their own. A host that answers over
// h1 moves to a transport with more, since h1 carries one request at a time
type secureTransport struct {
	h2, h1  http.RoundTripper
	h1Hosts sync.Map
}

func (t *secureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if _, ok := t.h1Hosts.Load(r.URL.Host); ok {
		return t.h1.RoundTrip(r)
	}
	resp, err := t.h2.RoundTrip(r)
	if err == nil && resp.ProtoMajor == 1 {
		t.h1Hosts.Store(r.URL.Host, true)
	}
	return resp, err
}
