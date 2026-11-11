package listener

import (
	"testing"

	IN "github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fallbacks of a VLESS or Trojan listener decode from the config as
// written, a dest given as a YAML integer included.
func TestParseListener_Fallbacks(t *testing.T) {
	const fallbacks = `
fallbacks:
  - dest: 8080
  - path: /app
    dest: 127.0.0.1:8081
    xver: 1
  - alpn: h2
    dest: /run/nginx/h2.sock
  - name: blog.example.com
    dest: "8082"
`
	want := []IN.Fallback{
		{Dest: "8080"},
		{Path: "/app", Dest: "127.0.0.1:8081", Xver: 1},
		{ALPN: "h2", Dest: "/run/nginx/h2.sock"},
		{Name: "blog.example.com", Dest: "8082"},
	}

	l, err := ParseListener(parseYAMLListener(t, `
name: vless-in
type: vless
listen: 127.0.0.1
port: 0
users:
  - uuid: 00000000-0000-0000-0000-000000000000
allow-insecure: true
`+fallbacks))
	require.NoError(t, err)
	vless, ok := l.Config().(*IN.VlessOption)
	require.True(t, ok)
	assert.Equal(t, want, vless.Fallbacks)

	l, err = ParseListener(parseYAMLListener(t, `
name: trojan-in
type: trojan
listen: 127.0.0.1
port: 0
users:
  - password: x
allow-insecure: true
`+fallbacks))
	require.NoError(t, err)
	trojan, ok := l.Config().(*IN.TrojanOption)
	require.True(t, ok)
	assert.Equal(t, want, trojan.Fallbacks)
}
