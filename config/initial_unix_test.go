//go:build unix

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitCreatesPrivateFiles(t *testing.T) {
	oldMask := syscall.Umask(0)
	defer syscall.Umask(oldMask)

	oldHome := C.Path.HomeDir()
	oldConfig := C.Path.Config()
	defer func() {
		C.SetHomeDir(oldHome)
		C.SetConfig(oldConfig)
	}()

	dir := filepath.Join(t.TempDir(), "citrus")
	C.SetHomeDir(dir)
	C.SetConfig(filepath.Join(dir, "config.yaml"))

	require.NoError(t, Init(dir))

	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())

	fileInfo, err := os.Stat(C.Path.Config())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm())
}
