//go:build unix

package resource

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSafeWriteCreatesPrivateFiles(t *testing.T) {
	oldMask := syscall.Umask(0)
	defer syscall.Umask(oldMask)

	dir := filepath.Join(t.TempDir(), "providers")
	path := filepath.Join(dir, "provider.yaml")
	require.NoError(t, safeWrite(path, []byte("payload: []")))

	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())

	fileInfo, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm())
}

func TestSafeWriteReplacesSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	require.NoError(t, os.WriteFile(victim, []byte("keep"), 0o600))
	path := filepath.Join(dir, "provider.yaml")
	require.NoError(t, os.Symlink(victim, path))

	require.NoError(t, safeWrite(path, []byte("payload: []")))

	data, err := os.ReadFile(victim)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(data), "write followed the symlink")
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	assert.True(t, fi.Mode().IsRegular())
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "payload: []", string(data))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "temporary file left behind")
}
