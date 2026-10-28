package config

import (
	"testing"

	"github.com/metacubex/mihomo/component/ca"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTLSRootPolicy(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte("tls: {}\n"))
	require.NoError(t, err)
	tlsCfg, err := parseTLS(raw)
	require.NoError(t, err)
	// both pools and the denylist on unless the config says otherwise
	assert.Equal(t, ca.RootPolicy{Source: ca.RootsBoth}, tlsCfg.RootPolicy)

	raw, err = UnmarshalRawConfig([]byte("tls:\n  ca-roots: bundle\n  ca-denylist: false\n"))
	require.NoError(t, err)
	tlsCfg, err = parseTLS(raw)
	require.NoError(t, err)
	assert.Equal(t, ca.RootPolicy{Source: ca.RootsBundle, DisableDenylist: true}, tlsCfg.RootPolicy)

	raw, err = UnmarshalRawConfig([]byte("tls:\n  ca-roots: builtin\n"))
	require.NoError(t, err)
	_, err = parseTLS(raw)
	assert.Error(t, err)
}
