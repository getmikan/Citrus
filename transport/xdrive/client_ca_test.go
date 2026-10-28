package xdrive

import (
	"context"
	stdtls "crypto/tls"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"testing"

	"github.com/metacubex/mihomo/component/ca/catest"
)

// The default storage client verifies against the pool of component/ca, a tls.custom-certifactes
// root is trusted.
func TestHTTPClientUsesCAPool(t *testing.T) {
	pki := catest.New(t)
	pki.Trust(t)

	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusNoContent)
	}))
	srv.TLS = &stdtls.Config{Certificates: []stdtls.Certificate{{Certificate: pki.Leaf.Certificate, PrivateKey: pki.Leaf.PrivateKey}}}
	srv.StartTLS()
	defer srv.Close()

	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	resp, err := NewHTTPClient(dial, nil).Get("https://" + catest.ServerName + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != stdhttp.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
