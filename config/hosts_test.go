package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHostsSelfWildcard(t *testing.T) {
	// the second entry walks into the first, which maps onto itself; that used
	// to loop forever whichever order the map was ranged in
	tree, err := parseHosts(&RawConfig{Hosts: map[string]any{
		"+.example.com": "example.com",
		"x.com":         "foo.example.com",
	}})
	require.NoError(t, err)
	assert.NotNil(t, tree.Search("x.com"))
}

func TestParseHostsCycle(t *testing.T) {
	_, err := parseHosts(&RawConfig{Hosts: map[string]any{
		"a.com": "b.com",
		"b.com": "a.com",
	}})
	assert.ErrorContains(t, err, "cycle")
}
