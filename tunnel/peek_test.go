package tunnel_test

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/stretchr/testify/assert"
)

// fakeProxy changes the type of a proxy, or makes it a group picking next.
type fakeProxy struct {
	C.Proxy
	typ  C.AdapterType
	next C.Proxy
}

func (p fakeProxy) Type() C.AdapterType { return p.typ }

func (p fakeProxy) Unwrap(*C.Metadata, bool) C.Proxy { return p.next }

func TestMayNeedHandshake(t *testing.T) {
	metadata := &C.Metadata{NetWork: C.TCP}
	direct := adapter.NewProxy(outbound.NewDirect())
	reject := adapter.NewProxy(outbound.NewReject())
	vless := fakeProxy{Proxy: direct, typ: C.Vless}
	group := func(next C.Proxy) C.Proxy { return fakeProxy{Proxy: direct, typ: C.Selector, next: next} }

	assert.False(t, tunnel.MayNeedHandshake(direct, metadata))
	assert.False(t, tunnel.MayNeedHandshake(reject, metadata))
	assert.True(t, tunnel.MayNeedHandshake(vless, metadata))
	assert.False(t, tunnel.MayNeedHandshake(group(group(direct)), metadata), "a group picking DIRECT")
	assert.True(t, tunnel.MayNeedHandshake(group(vless), metadata), "a group picking a proxy")
	assert.True(t, tunnel.MayNeedHandshake(group(nil), metadata), "a group picking nothing")
}
