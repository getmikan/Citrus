package httputils

import (
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newForwardedRequest(remoteAddr string, header string, values ...string) *http.Request {
	r := &http.Request{RemoteAddr: remoteAddr, Header: http.Header{}}
	for _, value := range values {
		r.Header.Add(header, value)
	}
	return r
}

func TestRealIPClientAddrPort(t *testing.T) {
	trusted := []string{"loopback", "private"}
	testCases := []struct {
		name     string
		header   string
		trusted  []string
		trustAny bool
		remote   string
		values   []string
		want     string // "" means: the peer is the client
	}{
		{name: "off", header: "", trusted: trusted, remote: "127.0.0.1:1000", values: []string{"203.0.113.7"}},
		{name: "no trusted proxies", header: "X-Forwarded-For", remote: "127.0.0.1:1000", values: []string{"203.0.113.7"}},
		{name: "untrusted peer", header: "X-Forwarded-For", trusted: trusted, remote: "198.51.100.1:1000", values: []string{"203.0.113.7"}},
		{name: "trusted peer", header: "X-Forwarded-For", trusted: trusted, remote: "127.0.0.1:1000", values: []string{"203.0.113.7"}, want: "203.0.113.7:0"},
		{name: "mapped peer", header: "X-Forwarded-For", trusted: trusted, remote: "[::ffff:10.0.0.2]:1000", values: []string{"203.0.113.7"}, want: "203.0.113.7:0"},
		{name: "ipv6 peer", header: "X-Forwarded-For", trusted: trusted, remote: "[::1]:1000", values: []string{"2001:db8::7"}, want: "[2001:db8::7]:0"},
		{name: "no header", header: "X-Forwarded-For", trusted: trusted, remote: "127.0.0.1:1000"},
		{name: "spoofed leftmost", header: "X-Forwarded-For", trusted: trusted, remote: "127.0.0.1:1000", values: []string{"6.6.6.6, 203.0.113.7"}, want: "203.0.113.7:0"},
		{name: "trusted hops skipped", header: "X-Forwarded-For", trusted: trusted, remote: "127.0.0.1:1000", values: []string{"6.6.6.6, 203.0.113.7, 10.1.1.1, 192.168.1.1"}, want: "203.0.113.7:0"},
		{name: "several header lines", header: "X-Forwarded-For", trusted: trusted, remote: "127.0.0.1:1000", values: []string{"6.6.6.6", "203.0.113.7, 10.1.1.1"}, want: "203.0.113.7:0"},
		{name: "all trusted", header: "X-Forwarded-For", trusted: trusted, remote: "127.0.0.1:1000", values: []string{"10.1.1.1, 192.168.1.1"}, want: "10.1.1.1:0"},
		{name: "garbage left of client", header: "X-Forwarded-For", trusted: trusted, remote: "127.0.0.1:1000", values: []string{"unknown, 203.0.113.7"}, want: "203.0.113.7:0"},
		{name: "garbage right", header: "X-Forwarded-For", trusted: trusted, remote: "127.0.0.1:1000", values: []string{"203.0.113.7, unknown"}},
		{name: "garbage after trusted hop", header: "X-Forwarded-For", trusted: trusted, remote: "127.0.0.1:1000", values: []string{"203.0.113.7, unknown, 10.1.1.1"}, want: "10.1.1.1:0"},
		{name: "with port", header: "X-Forwarded-For", trusted: trusted, remote: "127.0.0.1:1000", values: []string{"203.0.113.7:4321"}, want: "203.0.113.7:4321"},
		{name: "ipv6 with port", header: "X-Forwarded-For", trusted: trusted, remote: "127.0.0.1:1000", values: []string{"[2001:db8::7]:4321"}, want: "[2001:db8::7]:4321"},
		{name: "x-real-ip", header: "X-Real-IP", trusted: trusted, remote: "127.0.0.1:1000", values: []string{"203.0.113.7"}, want: "203.0.113.7:0"},
		{name: "cidr", header: "CF-Connecting-IP", trusted: []string{"198.51.100.0/24"}, remote: "198.51.100.9:1000", values: []string{"203.0.113.7"}, want: "203.0.113.7:0"},
		{name: "single address", header: "X-Forwarded-For", trusted: []string{"198.51.100.9"}, remote: "198.51.100.9:1000", values: []string{"203.0.113.7"}, want: "203.0.113.7:0"},
		{name: "single address mismatch", header: "X-Forwarded-For", trusted: []string{"198.51.100.9"}, remote: "198.51.100.10:1000", values: []string{"203.0.113.7"}},
		// the legacy mode of hysteria2-realm: leftmost value from any peer
		{name: "trust any", header: "X-Forwarded-For", trustAny: true, remote: "198.51.100.1:1000", values: []string{"6.6.6.6, 203.0.113.7"}, want: "6.6.6.6:0"},
		{name: "trust any with trusted proxies", header: "X-Forwarded-For", trusted: trusted, trustAny: true, remote: "198.51.100.1:1000", values: []string{"203.0.113.7"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			realIP, err := NewRealIP(testCase.header, testCase.trusted, testCase.trustAny)
			require.NoError(t, err)
			ap := realIP.ClientAddrPort(newForwardedRequest(testCase.remote, testCase.header, testCase.values...))
			if testCase.want == "" {
				assert.False(t, ap.IsValid(), ap.String())
			} else {
				assert.Equal(t, testCase.want, ap.String())
			}
		})
	}
}

func TestParseTrustedProxies(t *testing.T) {
	prefixes, err := ParseTrustedProxies([]string{" Loopback ", "private", "198.51.100.7", "2001:db8::/32", "::ffff:203.0.113.0/120", "192.0.2.77/24", ""})
	require.NoError(t, err)
	var got []string
	for _, prefix := range prefixes {
		got = append(got, prefix.String())
	}
	assert.Equal(t, []string{
		"127.0.0.0/8", "::1/128",
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
		"198.51.100.7/32", "2001:db8::/32", "203.0.113.0/24", "192.0.2.0/24",
	}, got)

	for _, invalid := range []string{"10.0.0.0/33", "example.com", "::ffff:0.0.0.0/64", "local"} {
		_, err := ParseTrustedProxies([]string{invalid})
		assert.Error(t, err, invalid)
	}
}

func TestClientNetAddr(t *testing.T) {
	peer := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	assert.Equal(t, "203.0.113.7:1000", ClientNetAddr(netip.MustParseAddrPort("203.0.113.7:0"), peer).String())
	assert.Equal(t, "203.0.113.7:4321", ClientNetAddr(netip.MustParseAddrPort("203.0.113.7:4321"), peer).String())
}
