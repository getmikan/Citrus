package mmdb

import (
	"net"
	"sync"
	"testing"

	mihomoOnce "github.com/metacubex/mihomo/common/once"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplaceIPWithLookupsInFlight(t *testing.T) {
	reader := buildTestMMDB(t, "sing-geoip", mmdbString("cn"))
	ipOnce.Do(func() { ipReader = IPReader{Reader: reader, databaseType: typeSing} })
	t.Cleanup(func() { mihomoOnce.Reset(&ipOnce) })

	snapshot := IPInstance()
	require.Equal(t, []string{"cn"}, snapshot.LookupCode(net.ParseIP("200.1.1.1")))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// A lookup on a reader closed under it must not fault.
				snapshot.LookupCode(net.ParseIP("200.1.1.1"))
			}
		}()
	}

	wrote := false
	err := ReplaceIP(func() error {
		wrote = true
		// The file is written only once no lookup can read the reader.
		assert.Error(t, reader.Lookup(net.ParseIP("200.1.1.1"), new(string)))
		return nil
	})
	close(stop)
	wg.Wait()
	require.NoError(t, err)
	assert.True(t, wrote)
	assert.False(t, mihomoOnce.Done(&ipOnce), "the next IPInstance must load the new file")
	assert.Empty(t, snapshot.LookupCode(net.ParseIP("200.1.1.1")))
}
