package openvpn

import (
	"net"
	"strings"
	"testing"

	"github.com/metacubex/tls"
)

func TestClientConfigTLSVersionMin(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want uint16
	}{
		{in: "", want: 0},
		{in: "1.2", want: tls.VersionTLS12},
		{in: " 1.3 ", want: tls.VersionTLS13},
	} {
		cfg := yamlStyleConfig()
		cfg.TLSVersionMin = tt.in
		if err := cfg.Prepare(); err != nil {
			t.Fatalf("%q: %v", tt.in, err)
		}
		if cfg.tlsMinVersion != tt.want {
			t.Fatalf("%q: min version %#x, want %#x", tt.in, cfg.tlsMinVersion, tt.want)
		}
	}

	for _, in := range []string{"1.0", "1.1", "1.4", "tls1.3", "1.2 or-highest"} {
		cfg := yamlStyleConfig()
		cfg.TLSVersionMin = in
		if err := cfg.Prepare(); err == nil || !strings.Contains(err.Error(), "tls-version-min") {
			t.Fatalf("%q accepted: %v", in, err)
		}
	}
}

// The control channel refuses a TLS 1.2 server only when asked to.
func TestTLSVersionMinAgainstTLS12Server(t *testing.T) {
	serverCert, caPEM := newTestTLSServerCertificate(t)

	for _, tt := range []struct {
		min     string
		wantErr bool
	}{
		{min: "", wantErr: false},
		{min: "1.2", wantErr: false},
		{min: "1.3", wantErr: true},
	} {
		cfg := yamlStyleConfig()
		cfg.CA = caPEM
		cfg.Cert, cfg.Key = nil, nil
		cfg.Username = "user"
		cfg.TLSVersionMin = tt.min
		if err := cfg.Prepare(); err != nil {
			t.Fatal(err)
		}
		tlsConfig, err := (&Client{config: cfg}).tlsConfig()
		if err != nil {
			t.Fatal(err)
		}

		clientSide, serverSide := net.Pipe()
		server := tls.Server(serverSide, &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			MaxVersion:   tls.VersionTLS12,
		})
		go func() {
			_ = server.Handshake()
			_ = serverSide.Close()
		}()
		client := tls.Client(clientSide, tlsConfig)
		err = client.Handshake()
		_ = clientSide.Close()

		if tt.wantErr != (err != nil) {
			t.Fatalf("tls-version-min %q: handshake error %v, want error %v", tt.min, err, tt.wantErr)
		}
		if err == nil && client.ConnectionState().Version != tls.VersionTLS12 {
			t.Fatalf("tls-version-min %q: negotiated %#x", tt.min, client.ConnectionState().Version)
		}
	}
}
