package outbound

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/metacubex/mihomo/transport/xdrive"
)

func TestXDriveHTTPSClient(t *testing.T) {
	for _, fronting := range []bool{false, true} {
		t.Run(fmt.Sprint(fronting), func(t *testing.T) {
			seen := make(chan *http.Request, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r; _, _ = io.WriteString(w, "ok") }))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			cfg := &xdrive.Config{Service: "local", RemoteFolder: t.TempDir()}
			target := server.URL
			if fronting {
				cfg.Fronting = server.Listener.Addr().String()
				target = "https://storage.test/"
			}
			v, err := NewVless(VlessOption{Name: "x", Server: "unused.invalid", Port: 443, UUID: "27848739-7e62-4138-9fd3-098a63964b6b", Network: "xdrive", Encryption: "mlkem768x25519plus.native.0rtt.XKbaq1BuzJKKKPxZbwgRpn-gYQbnhrYketgezASCL1I", XDriveOpts: cfg, SkipCertVerify: true})
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			client := v.newXDriveHTTPClient()
			defer client.CloseIdleConnections()
			resp, err := client.Get(target)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.ProtoMajor != 2 {
				t.Fatalf("expected HTTP/2, got %s", resp.Proto)
			}
			request := <-seen
			if fronting && (request.Host != "storage.test" || request.TLS.ServerName != "storage.test") {
				t.Fatalf("fronting changed Host or SNI: %s / %s", request.Host, request.TLS.ServerName)
			}
		})
	}
}
