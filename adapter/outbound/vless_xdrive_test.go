package outbound

import (
	"github.com/metacubex/mihomo/transport/xdrive"
	"testing"
)

func TestVlessXDriveValidation(t *testing.T) {
	valid := VlessOption{Name: "x", UUID: "27848739-7e62-4138-9fd3-098a63964b6b", Network: "xdrive", Encryption: "mlkem768x25519plus.native.0rtt.XKbaq1BuzJKKKPxZbwgRpn-gYQbnhrYketgezASCL1I", XDriveOpts: &xdrive.Config{Service: "local", RemoteFolder: t.TempDir()}}
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
