package outbound

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/egress"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
)

// The desync outbound dials on its own, so it applies the egress guard as
// DIRECT does: a server inbound user cannot reach the loopback through it,
// by an IP literal or a domain, while client inbounds are untouched.
func TestDesyncEgressGuardTCP(t *testing.T) {
	withEgressOptions(t, egress.Options{Enable: true})
	target := acceptAll(t)
	withDirectResolver(t, &listResolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}})
	d := newTestDesync(t, DesyncOption{TLSRec: "1+s"})

	dial := func(metadata *C.Metadata) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := d.DialContext(ctx, metadata)
		if err == nil {
			_ = c.Close()
		}
		return err
	}
	literal := func(typ C.Type) *C.Metadata {
		return &C.Metadata{NetWork: C.TCP, Type: typ, InName: "in", DstIP: target.Addr(), DstPort: target.Port()}
	}
	domain := &C.Metadata{NetWork: C.TCP, Type: C.TROJAN, InName: "in", Host: "rebind.example", DstPort: target.Port()}

	assert.ErrorIs(t, dial(literal(C.VLESS)), egress.ErrBlocked, "an IP literal of the loopback")
	assert.ErrorIs(t, dial(domain), egress.ErrBlocked, "a domain that resolves to the loopback")
	assert.NoError(t, dial(literal(C.SOCKS5)), "client inbounds are untouched")
}
