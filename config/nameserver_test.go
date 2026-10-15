package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNameServerKeepsDoHUserinfo(t *testing.T) {
	servers, err := parseNameServer([]string{"https://user:s3cret@dns.example.com/dns-query"}, false, false)
	require.NoError(t, err)
	require.Len(t, servers, 1)
	assert.Equal(t, "https", servers[0].Net)
	assert.Equal(t, "https://user:s3cret@dns.example.com:443/dns-query", servers[0].Addr)
}

func TestParseNameServerErrorHidesUserinfo(t *testing.T) {
	_, err := parseNameServer([]string{"https://user:s3cret@[::1/dns-query"}, false, false)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "s3cret")
}

func TestParseNameServerDNSCrypt(t *testing.T) {
	const stamp = "sdns://AQMAAAAAAAAAEzE0OS4xMTIuMTEyLjEwOjg0NDMgZ8hHuMh1jNEgJFVDvnVnRt803x2EwAuMRwNo34Idhj4ZMi5kbnNjcnlwdC1jZXJ0LnF1YWQ5Lm5ldA"
	servers, err := parseNameServer([]string{stamp + "#Proxy&disable-ipv6=true", stamp}, false, false)
	require.NoError(t, err)
	require.Len(t, servers, 2)
	assert.Equal(t, "dnscrypt", servers[0].Net)
	assert.Equal(t, stamp, servers[0].Addr)
	assert.Equal(t, "Proxy", servers[0].ProxyName)
	assert.Equal(t, "true", servers[0].Params["disable-ipv6"])
	assert.Equal(t, stamp, servers[1].Addr)
	assert.Empty(t, servers[1].ProxyName)

	servers, err = parseNameServer([]string{stamp}, true, false)
	require.NoError(t, err)
	assert.Equal(t, "RULES", servers[0].ProxyName)

	_, err = parseNameServer([]string{"sdns://AgUAAAAAAAAAAAAOZG5zLmdvb2dsZS5jb20NL2V4cGVyaW1lbnRhbA"}, false, false)
	assert.ErrorContains(t, err, "https://")
	_, err = parseNameServer([]string{"sdns://AQ"}, false, false)
	assert.Error(t, err)
}
