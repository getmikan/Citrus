//go:build unix

package cachefile

import (
	"os"
	"syscall"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheFileIsPrivate(t *testing.T) {
	oldMask := syscall.Umask(0)
	defer syscall.Umask(oldMask)

	oldHome := C.Path.HomeDir()
	defer C.SetHomeDir(oldHome)
	C.SetHomeDir(t.TempDir())

	initCache()
	require.NotNil(t, defaultCache.DB)
	defer defaultCache.Close()

	info, err := os.Stat(C.Path.Cache())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}
