package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The defaults keep the resolver's pre-existing behaviour: answer stale at once,
// refresh in the background, no age limit.
func TestParseDNSServeExpiredDefaultsKeepExistingBehaviour(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte("mode: rule\n"))
	require.NoError(t, err)

	dns, err := parseDNS(raw, nil)
	require.NoError(t, err)
	require.True(t, dns.ServeExpired)
	require.Equal(t, time.Duration(0), dns.ServeExpiredTTL)
	require.Equal(t, time.Duration(0), dns.ServeExpiredClientTimeout)
}

func TestParseDNSServeExpired(t *testing.T) {
	tests := []struct {
		name          string
		yaml          string
		wantErr       bool
		ttl           time.Duration
		clientTimeout time.Duration
	}{
		{
			name:          "enabled",
			yaml:          "dns:\n  serve-expired: true\n  serve-expired-ttl: 3600\n  serve-expired-client-timeout: 500\n",
			ttl:           time.Hour,
			clientTimeout: 500 * time.Millisecond,
		},
		{
			name: "unlimited and immediate",
			yaml: "dns:\n  serve-expired: true\n  serve-expired-ttl: 0\n  serve-expired-client-timeout: 0\n",
		},
		{
			name:          "upper bounds",
			yaml:          "dns:\n  serve-expired: true\n  serve-expired-ttl: 2592000\n  serve-expired-client-timeout: 5000\n",
			ttl:           30 * 24 * time.Hour,
			clientTimeout: 5 * time.Second,
		},
		{
			name:    "ttl above 30 days",
			yaml:    "dns:\n  serve-expired-ttl: 2592001\n",
			wantErr: true,
		},
		{
			name:    "client timeout above the DNS timeout",
			yaml:    "dns:\n  serve-expired-client-timeout: 5001\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := UnmarshalRawConfig([]byte(tt.yaml))
			require.NoError(t, err)

			dns, err := parseDNS(raw, nil)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.True(t, dns.ServeExpired)
			require.Equal(t, tt.ttl, dns.ServeExpiredTTL)
			require.Equal(t, tt.clientTimeout, dns.ServeExpiredClientTimeout)
		})
	}
}

func TestParseDNSServeExpiredRejectsNegative(t *testing.T) {
	_, err := UnmarshalRawConfig([]byte("dns:\n  serve-expired-ttl: -1\n"))
	require.Error(t, err)
}
