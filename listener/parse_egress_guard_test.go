package listener

import (
	"testing"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The listener's egress-guard reaches the metadata of its connections; unset
// leaves the choice to the global setting.
func TestParseListenerEgressGuard(t *testing.T) {
	for _, tc := range []struct {
		value any
		want  C.EgressGuard
	}{
		{nil, C.EgressGuardDefault},
		{true, C.EgressGuardOn},
		{false, C.EgressGuardOff},
	} {
		mapping := map[string]any{"name": "socks-in", "type": "socks", "port": 0, "listen": "127.0.0.1"}
		if tc.value != nil {
			mapping["egress-guard"] = tc.value
		}
		l, err := ParseListener(mapping)
		require.NoError(t, err, "%v", tc.value)

		withAdditions, ok := l.(interface{ Additions() []inbound.Addition })
		require.True(t, ok)
		metadata := &C.Metadata{}
		inbound.ApplyAdditions(metadata, withAdditions.Additions()...)
		assert.Equal(t, tc.want, metadata.EgressGuard, "egress-guard: %v", tc.value)
		assert.Equal(t, "socks-in", metadata.InName)
	}
}
