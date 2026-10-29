package outbound

import (
	"errors"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/xdrive"
)

func xdriveTestOption(cfg *xdrive.Config) VlessOption {
	return VlessOption{Name: "x", UUID: "27848739-7e62-4138-9fd3-098a63964b6b", Network: "xdrive", Encryption: "mlkem768x25519plus.native.0rtt.XKbaq1BuzJKKKPxZbwgRpn-gYQbnhrYketgezASCL1I", XDriveOpts: cfg}
}

// A template NewVless accepts, so a refusal can only come from the remote
// source check.
func xdriveTestTemplate() *xdrive.Config {
	return &xdrive.Config{Service: "template", RemoteFolder: "f", Template: map[string]any{
		"put":    map[string]any{"method": "PUT", "url": "http://127.0.0.1:1/{folder}/{name}"},
		"get":    map[string]any{"method": "GET", "url": "http://127.0.0.1:1/{folder}/{name}"},
		"delete": map[string]any{"method": "DELETE", "url": "http://127.0.0.1:1/{folder}/{name}"},
		"list":   map[string]any{"method": "GET", "url": "http://127.0.0.1:1/{folder}/", "namesRegex": `"([^"]+)"`},
	}}
}

func TestVlessXDriveRemoteSourceSkipsLocalServices(t *testing.T) {
	for name, cfg := range map[string]*xdrive.Config{
		"local":    {Service: "local", RemoteFolder: t.TempDir()},
		"template": xdriveTestTemplate(),
	} {
		t.Run(name, func(t *testing.T) {
			o := xdriveTestOption(cfg)
			o.ProviderName = "sub"
			v, err := NewVless(o)
			if err != nil {
				t.Fatalf("user-written provider entry refused: %v", err)
			}
			v.Close()

			o.RemoteSource = true
			if v, err := NewVless(o); !errors.Is(err, C.ErrProviderSkip) {
				if err == nil {
					v.Close()
				}
				t.Fatalf("want ErrProviderSkip, got %v", err)
			}
		})
	}
}

func TestVlessXDriveRemoteSourceAllowsGoogleDrive(t *testing.T) {
	o := xdriveTestOption(&xdrive.Config{Service: "google-drive", RemoteFolder: "f", Secrets: []string{"id", "secret", "refresh"}})
	o.ProviderName = "sub"
	o.RemoteSource = true
	v, err := NewVless(o)
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
}

func TestVlessXDriveValidation(t *testing.T) {
	valid := xdriveTestOption(&xdrive.Config{Service: "local", RemoteFolder: t.TempDir()})
	v, err := NewVless(valid)
	if err != nil {
		t.Fatal(err)
	}
	if v.xdriveClient == nil || v.xdriveMux == nil {
		t.Fatal("XDRIVE was not initialized")
	}
	v.Close()
	for name, change := range map[string]func(*VlessOption){
		"missing-options":  func(o *VlessOption) { o.XDriveOpts = nil },
		"no-encryption":    func(o *VlessOption) { o.Encryption = "none" },
		"empty-encryption": func(o *VlessOption) { o.Encryption = "" },
		"flow":             func(o *VlessOption) { o.Flow = "xtls-rprx-vision" },
		"packetaddr":       func(o *VlessOption) { o.PacketEncoding = "packetaddr" },
	} {
		t.Run(name, func(t *testing.T) {
			o := valid
			change(&o)
			if v, err := NewVless(o); err == nil {
				v.Close()
				t.Fatal("invalid XDRIVE configuration accepted")
			}
		})
	}
}
