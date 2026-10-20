package adapter

import "testing"

func TestParseXDriveDefaults(t *testing.T) {
	mapping := map[string]any{"name": "xdrive", "type": "vless", "server": "127.0.0.1", "port": 443, "uuid": "27848739-7e62-4138-9fd3-098a63964b6b", "network": "xdrive", "encryption": "mlkem768x25519plus.native.0rtt.XKbaq1BuzJKKKPxZbwgRpn-gYQbnhrYketgezASCL1I", "xdrive-opts": map[string]any{"service": "local", "remote-folder": t.TempDir()}}
	p, err := ParseProxy(mapping)
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	mapping["smux"] = map[string]any{"enabled": true}
	if p, err := ParseProxy(mapping); err == nil {
		p.Close()
		t.Fatal("accepted incompatible smux wrapper")
	}
}
