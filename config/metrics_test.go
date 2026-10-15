package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMetrics(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte("mode: direct\n"))
	require.NoError(t, err)
	assert.Equal(t, &Metrics{}, parseMetrics(raw), "off by default; the probes require the secret")

	raw, err = UnmarshalRawConfig([]byte("mode: direct\nmetrics:\n  enable: true\n  per-user: true\nhealth-without-auth: true\n"))
	require.NoError(t, err)
	assert.Equal(t, &Metrics{Enable: true, PerUser: true, HealthWithoutAuth: true}, parseMetrics(raw))
}
