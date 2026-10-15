package sniffer

import (
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDispatcherSkipThreshold(t *testing.T) {
	metadata := &C.Metadata{
		NetWork: C.TCP,
		DstIP:   netip.MustParseAddr("192.0.2.1"),
		DstPort: 443,
	}
	dst := metadata.AddrPort()
	intPtr := func(v int) *int { return &v }

	// failures it takes before dst is skipped, 0 = never
	for _, tt := range []struct {
		name      string
		threshold *int
		skipAfter int
	}{
		{name: "default", threshold: nil, skipAfter: 6},
		{name: "zero skips after the first failure", threshold: intPtr(0), skipAfter: 1},
		{name: "above the old uint8 cap", threshold: intPtr(200), skipAfter: 201},
		{name: "largest", threshold: intPtr(MaxSkipThreshold), skipAfter: MaxSkipThreshold + 1},
		{name: "never", threshold: intPtr(-1), skipAfter: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := NewDispatcher(&Config{Enable: true, SkipThreshold: tt.threshold})
			require.NoError(t, err)

			rounds := tt.skipAfter
			if rounds == 0 {
				rounds = 300
			}
			for i := 1; i <= rounds+10; i++ {
				sd.cacheSniffFailed(metadata)
				want := tt.skipAfter != 0 && i >= tt.skipAfter
				require.Equal(t, want, sd.skipFailed(dst), "after %d failures", i)
			}
			if tt.skipAfter == 0 {
				_, cached := sd.skipList.Get(dst)
				assert.False(t, cached, "failures are not even counted")
			}
		})
	}

	_, err := NewDispatcher(&Config{SkipThreshold: intPtr(MaxSkipThreshold + 1)})
	assert.Error(t, err)
}
