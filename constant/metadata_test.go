package constant

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetadataLogAddress(t *testing.T) {
	m := &Metadata{DstIP: netip.MustParseAddr("1.2.3.4"), DstPort: 443}
	assert.Equal(t, "1.2.3.4:443", m.LogAddress(), "nothing sniffed")

	m.SniffHost = "example.com"
	assert.Equal(t, "1.2.3.4:443 (example.com)", m.LogAddress())
	assert.Equal(t, "1.2.3.4:443", m.RemoteAddress(), "the destination stays the IP")

	m.Host = "example.com" // override-destination
	assert.Equal(t, "example.com:443", m.LogAddress())

	m.Host = "other.com"
	assert.Equal(t, "other.com:443 (example.com)", m.LogAddress())

	v6 := &Metadata{DstIP: netip.MustParseAddr("2001:db8::1"), DstPort: 443, SniffHost: "example.com"}
	assert.Equal(t, "[2001:db8::1]:443 (example.com)", v6.LogAddress())
}
