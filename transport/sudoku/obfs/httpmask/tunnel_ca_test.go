package httpmask

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca/catest"

	"github.com/gobwas/ws"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

// The wss client verifies against the pool of component/ca, a tls.custom-certifactes root is trusted.
func TestDialWSUsesCAPool(t *testing.T) {
	pki := catest.New(t)
	pki.Trust(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{pki.Leaf}})
		if _, err := ws.Upgrade(tlsConn); err != nil {
			return
		}
		_, _ = tlsConn.Read(make([]byte, 1))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialWS(ctx, ln.Addr().String(), TunnelDialOptions{
		TLSEnabled:   true,
		HostOverride: catest.ServerName,
		DialContext:  (&net.Dialer{}).DialContext,
	})
	require.NoError(t, err)
	_ = conn.Close()
}

func TestPreconnectTLSFallbackUsesCAPool(t *testing.T) {
	pki := catest.New(t)
	pki.Trust(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{pki.Leaf}}).Handshake()
	}()

	urlHost := net.JoinHostPort(catest.ServerName, "443")
	d := newPreconnectDialer(urlHost, ln.Addr().String(), catest.ServerName, nil, (&net.Dialer{}).DialContext)
	conn, err := d.dialTLSFresh(context.Background(), "tcp", urlHost)
	require.NoError(t, err)
	_ = conn.Close()
}
