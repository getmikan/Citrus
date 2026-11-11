package hysteria2_realm

import (
	"testing"

	"github.com/metacubex/mihomo/common/httputils"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientIP(t *testing.T) {
	request := func(remote, xff string) *http.Request {
		r := &http.Request{RemoteAddr: remote, Header: http.Header{}}
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	// no trusted-proxies: the header is not believed from anybody
	untrusted, err := httputils.NewRealIP("X-Forwarded-For", nil, false)
	require.NoError(t, err)
	assert.Equal(t, "198.51.100.1", clientIP(request("198.51.100.1:1000", "6.6.6.6, 203.0.113.7"), untrusted))
	assert.Equal(t, "198.51.100.1", clientIP(request("198.51.100.1:1000", ""), untrusted))

	trusted, err := httputils.NewRealIP("X-Forwarded-For", []string{"loopback"}, false)
	require.NoError(t, err)
	assert.Equal(t, "198.51.100.1", clientIP(request("198.51.100.1:1000", "203.0.113.7"), trusted))
	assert.Equal(t, "203.0.113.7", clientIP(request("127.0.0.1:1000", "6.6.6.6, 203.0.113.7"), trusted))
	assert.Equal(t, "127.0.0.1", clientIP(request("[::ffff:127.0.0.1]:1000", ""), trusted))

	off, err := httputils.NewRealIP("", nil, false)
	require.NoError(t, err)
	assert.Equal(t, "198.51.100.1", clientIP(request("198.51.100.1:1000", "203.0.113.7"), off))
}

// The realm token is compared in constant time; the comparison must still
// accept only the exact token, and nothing when no token is set.
func TestCheckRealmToken(t *testing.T) {
	check := func(token, header string) bool {
		r, err := http.NewRequest(http.MethodPost, "http://realm/v1/x", nil)
		require.NoError(t, err)
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		return newServer(serverConfig{realmToken: token}).checkRealmToken(r)
	}
	assert.True(t, check("realm-token", "Bearer realm-token"))
	assert.False(t, check("realm-token", "Bearer realm-tokeN"))
	assert.False(t, check("realm-token", "Bearer realm-token2"))
	assert.False(t, check("realm-token", "Bearer realm"))
	assert.False(t, check("realm-token", "Bearer "))
	assert.False(t, check("realm-token", "realm-token"))
	assert.False(t, check("realm-token", ""))
	assert.False(t, check("", "Bearer "))
	assert.False(t, check("", ""))
}
