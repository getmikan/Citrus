package outbound

import (
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/xhttp"

	"github.com/stretchr/testify/assert"
)

func TestXHTTPReuseSettingsDefault(t *testing.T) {
	for _, settings := range []*XHTTPReuseSettings{nil, {}} {
		cfg, keepAlive := settings.build(false)
		assert.Equal(t, xhttp.DefaultReuseConfig(), cfg)
		assert.Zero(t, keepAlive)

		// no default XMUX over HTTP/1.1
		cfg, keepAlive = settings.build(true)
		assert.Nil(t, cfg)
		assert.Zero(t, keepAlive)
	}

	// explicit settings stay authoritative, even when they disable the reuse
	for _, http1 := range []bool{false, true} {
		cfg, keepAlive := (&XHTTPReuseSettings{MaxConnections: "0", HKeepAlivePeriod: 30}).build(http1)
		assert.Equal(t, &xhttp.ReuseConfig{MaxConnections: "0"}, cfg)
		assert.Equal(t, 30*time.Second, keepAlive)
	}
}
