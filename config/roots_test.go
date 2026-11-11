package config_test

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ca/catest"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"

	"github.com/metacubex/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serveHTTPSProxy answers CONNECT requests over TLS with the leaf of pki.
func serveHTTPSProxy(t *testing.T, pki *catest.PKI) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{pki.Leaf}})
				if _, err := http.ReadRequest(bufio.NewReader(tlsConn)); err != nil {
					return
				}
				_, _ = tlsConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
				_, _ = tlsConn.Read(make([]byte, 1))
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func tlsProxyConfig(t *testing.T, tlsCfg map[string]any, port int, rule string) []byte {
	t.Helper()
	buf, err := json.Marshal(map[string]any{
		"tls": tlsCfg,
		"proxies": []map[string]any{{
			"name": "https", "type": "http", "server": "127.0.0.1", "port": port, "tls": true, "sni": catest.ServerName,
		}},
		"rules": []string{rule},
	})
	require.NoError(t, err)
	return buf
}

// The proxies keep the root pool they are built with, so the pool of the config being parsed must be
// in place before them: ca-roots and custom-certifactes reach them on the first start.
func TestParseInstallsRootsBeforeProxies(t *testing.T) {
	prev := ca.SwapRoots(nil)
	t.Cleanup(func() { ca.SwapRoots(prev) })
	pki := catest.New(t)
	port := serveHTTPSProxy(t, pki)

	dial := func(cfg *config.Config) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := cfg.Proxies["https"].DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "example.com", DstPort: 80})
		if err == nil {
			_ = conn.Close()
		}
		return err
	}

	tlsCfg := map[string]any{"ca-roots": "bundle", "custom-certifactes": []string{pki.RootPEM}}
	cfg, err := executor.ParseWithBytes(tlsProxyConfig(t, tlsCfg, port, "MATCH,https"))
	require.NoError(t, err)
	assert.NoError(t, dial(cfg))

	// a config that fails to parse puts the roots back
	installed := ca.GetCertPool()
	_, err = executor.ParseWithBytes(tlsProxyConfig(t, map[string]any{"ca-roots": "system"}, port, "MATCH,missing"))
	require.Error(t, err)
	assert.Same(t, installed, ca.GetCertPool())

	// the next config without the custom root: its proxies do not trust it, before any ApplyConfig
	cfg, err = executor.ParseWithBytes(tlsProxyConfig(t, map[string]any{"ca-roots": "bundle"}, port, "MATCH,https"))
	require.NoError(t, err)
	var unknown x509.UnknownAuthorityError
	assert.ErrorAs(t, dial(cfg), &unknown)
}
