package listener

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/common/yaml"
	IN "github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseYAMLListener(t *testing.T, doc string) map[string]any {
	t.Helper()
	var mapping map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(doc), &mapping))
	return mapping
}

func TestParseListener_Unix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "in.sock")
	listen := "unix:" + path
	for _, tt := range []struct {
		typ   string
		extra map[string]any
	}{
		{typ: "http"},
		{typ: "socks"},
		{typ: "mixed"},
		{typ: "shadowsocks", extra: map[string]any{"cipher": "aes-128-gcm", "password": "test"}},
		{typ: "snell", extra: map[string]any{"psk": "test"}},
		{typ: "vless", extra: map[string]any{"users": []map[string]any{{"uuid": "00000000-0000-0000-0000-000000000000"}}, "allow-insecure": true}},
		{typ: "trojan", extra: map[string]any{"users": []map[string]any{{"password": "test"}}}},
		{typ: "anytls", extra: map[string]any{"users": map[string]any{"test": "test"}}},
		{typ: "sudoku", extra: map[string]any{"key": "test"}},
		{typ: "tunnel", extra: map[string]any{"network": []string{"tcp"}, "target": "127.0.0.1:80"}},
		{typ: "trusttunnel", extra: map[string]any{"certificate": "test", "private-key": "test"}},
		{typ: "hysteria2-realm", extra: map[string]any{"token": "test"}},
	} {
		t.Run(tt.typ, func(t *testing.T) {
			mapping := map[string]any{"name": "unix-in", "type": tt.typ, "listen": listen}
			for k, v := range tt.extra {
				mapping[k] = v
			}
			l, err := ParseListener(mapping)
			require.NoError(t, err)
			assert.Equal(t, listen, l.RawAddress())
			// UDP is off by default on a unix socket
			switch config := l.Config().(type) {
			case *IN.SocksOption:
				assert.False(t, config.UDP)
			case *IN.MixedOption:
				assert.False(t, config.UDP)
			case *IN.ShadowSocksOption:
				assert.False(t, config.UDP)
			}
		})
	}
}

func TestParseListener_UnixRejected(t *testing.T) {
	listen := "unix:" + filepath.Join(t.TempDir(), "in.sock")
	for _, mapping := range []map[string]any{
		{"type": "hysteria2", "certificate": "test", "private-key": "test"},
		{"type": "tuic", "certificate": "test", "private-key": "test"},
		{"type": "mieru", "transport": "TCP", "users": map[string]any{"test": "test"}},
		{"type": "redir"},
		{"type": "tproxy"},
		{"type": "socks", "udp": true},
		{"type": "mixed", "udp": true},
		{"type": "shadowsocks", "cipher": "aes-128-gcm", "password": "test", "udp": true},
		{"type": "tunnel", "network": []string{"udp"}, "target": "127.0.0.1:53"},
		{"type": "trusttunnel", "certificate": "test", "private-key": "test", "network": []string{"tcp", "udp"}},
		{"type": "http", "port": 7890},
	} {
		mapping["name"] = "unix-in"
		mapping["listen"] = listen
		_, err := ParseListener(mapping)
		if assert.Error(t, err, mapping["type"]) {
			assert.True(t, strings.Contains(err.Error(), "unix socket"), err.Error())
		}
	}
}

func TestParseListener_TCPKeepsUDPDefault(t *testing.T) {
	l, err := ParseListener(map[string]any{"name": "socks-in", "type": "socks", "port": 0})
	require.NoError(t, err)
	assert.True(t, l.Config().(*IN.SocksOption).UDP)
}

func TestParseListener_UnixMode(t *testing.T) {
	listen := "unix:" + filepath.Join(t.TempDir(), "in.sock")
	for _, tt := range []struct {
		value string
		want  fs.FileMode
		err   bool
	}{
		{value: "0660", want: 0o660},
		{value: "0o640", want: 0o640},
		{value: `"0600"`, want: 0o600},
		{value: `"0o666"`, want: 0o666},
		{value: "660", err: true}, // decimal 660 is not a mode
		{value: "01777", err: true},
	} {
		t.Run(tt.value, func(t *testing.T) {
			mapping := parseYAMLListener(t, "name: m\ntype: http\nlisten: "+listen+"\nunix-mode: "+tt.value+"\n")
			l, err := ParseListener(mapping)
			if tt.err {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, int(tt.want), l.Config().(*IN.HTTPOption).UnixMode)
		})
	}
}
