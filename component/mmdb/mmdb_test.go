package mmdb

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	mihomoOnce "github.com/metacubex/mihomo/common/once"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReplaceIPWithLookupsInFlight loads the database from a file, so the
// reader is memory-mapped as in production: a lookup that ran while
// ReplaceIP closed the reader could read an unmapped buffer and fault. That
// fault depends on timing; the misses check (a lookup reaching the closed
// reader) fails deterministically, and -race catches unlocked access.
func TestReplaceIPWithLookupsInFlight(t *testing.T) {
	oldHome := C.Path.HomeDir()
	dir := t.TempDir()
	C.SetHomeDir(dir)
	path := filepath.Join(dir, "geoip.metadb")
	require.NoError(t, os.WriteFile(path, buildTestMMDBBytes("sing-geoip", mmdbString("cn")), 0o644))
	mihomoOnce.Reset(&ipOnce)
	t.Cleanup(func() {
		if mihomoOnce.Done(&ipOnce) && ipReader.Reader != nil {
			_ = ipReader.Reader.Close()
		}
		mihomoOnce.Reset(&ipOnce)
		C.SetHomeDir(oldHome)
	})

	ip := net.ParseIP("200.1.1.1")
	snapshot := IPInstance()
	require.Equal(t, []string{"cn"}, snapshot.LookupCode(ip))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var misses atomic.Int32
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
				snapshot.LookupCode(ip)
				// The package-level lookup always sees a loaded database:
				// the old one or the new one, never the closed one.
				if codes := LookupCode(ip); len(codes) != 1 || (codes[0] != "cn" && codes[0] != "us") {
					misses.Add(1)
				}
			}
		}()
	}

	// Replace repeatedly to widen the window between loading the reader
	// and looking it up.
	for i := 0; i < 100; i++ {
		code := []string{"us", "cn"}[i%2]
		wrote := false
		err := ReplaceIP(func() error {
			wrote = true
			// The file is written only once no lookup can read the reader.
			assert.Error(t, snapshot.Lookup(ip, new(string)))
			return os.WriteFile(path, buildTestMMDBBytes("sing-geoip", mmdbString(code)), 0o644)
		})
		require.NoError(t, err)
		require.True(t, wrote)
		require.Equal(t, []string{code}, LookupCode(ip), "the next lookup must load the new file")
	}
	close(stop)
	wg.Wait()
	assert.Zero(t, misses.Load(), "a lookup racing ReplaceIP reported no match")
	assert.Empty(t, snapshot.LookupCode(ip))
}
