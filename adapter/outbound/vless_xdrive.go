package outbound

import (
	"context"
	"net"
	"time"

	"github.com/metacubex/http"
	N "github.com/metacubex/mihomo/common/net"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/transport/v2ray"
	"github.com/metacubex/mihomo/transport/vless"
	"github.com/metacubex/mihomo/transport/xdrive"
	"github.com/metacubex/tls"
)

func (v *Vless) newXDriveHTTPClient() *http.Client {
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Fronting overrides the connection address, while HTTP Host and TLS
		// SNI continue to follow the storage operation URL.
		if fronting := v.option.XDriveOpts.Fronting; fronting != "" {
			addr = fronting
		}
		return v.dialer.DialContext(ctx, network, addr)
	}
	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			raw.Close()
			return nil, err
		}
		if v.option.ServerName != "" {
			host = v.option.ServerName
		}
		alpn := v.option.ALPN
		if len(alpn) == 0 {
			alpn = []string{"h2", "http/1.1"}
		}
		fp := v.option.ClientFingerprint
		if fp == "" {
			fp = "chrome"
		}
		handshakeCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		conn, err := v2ray.StreamTLSConn(handshakeCtx, raw, &v2ray.TLSConfig{
			Host: host, NextProtos: alpn, SkipCertVerify: v.option.SkipCertVerify, NameCertVerify: v.option.NameCertVerify,
			FingerPrint: v.option.Fingerprint, Certificate: v.option.Certificate, PrivateKey: v.option.PrivateKey,
			ClientFingerprint: fp, ECH: v.echConfig,
		})
		if err != nil {
			raw.Close()
			return nil, err
		}
		return &xdriveTLSConn{Conn: conn}, nil
	}
	return xdrive.NewHTTPClient(dial, dialTLS)
}

// uTLS and the HTTP stack use different ConnectionState types. Expose the
// negotiated state in the HTTP stack's type so ALPN selects HTTP/2 correctly.
type xdriveTLSConn struct{ net.Conn }

func (c *xdriveTLSConn) ConnectionState() tls.ConnectionState {
	return tlsC.GetTLSConnectionState(c.Conn)
}
func (c *xdriveTLSConn) HandshakeContext(ctx context.Context) error { return ctx.Err() }
func (c *xdriveTLSConn) NetConn() net.Conn {
	if conn, ok := c.Conn.(interface{ NetConn() net.Conn }); ok {
		return conn.NetConn()
	}
	return c.Conn
}

var _ http.TLSConn = (*xdriveTLSConn)(nil)

func (v *Vless) newXDriveMuxConn(ctx context.Context) (conn net.Conn, err error) {
	raw, err := v.xdriveClient.Dial(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = raw.Close()
		}
	}()
	done := N.SetupContextForConn(ctx, raw)
	defer done(&err)
	_ = raw.SetDeadline(time.Now().Add(30 * time.Second))
	conn, err = v.encryption.Handshake(raw)
	if err != nil {
		return nil, err
	}
	conn, err = v.client.StreamConn(conn, &vless.DstAddr{Mux: true})
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return conn, nil
}
