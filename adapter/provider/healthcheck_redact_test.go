package provider

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedactURLForLog(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"https://www.gstatic.com/generate_204", "https://www.gstatic.com/generate_204"},
		{"https://user:secret@example.com/check", "https://user:xxxxx@example.com/check"},
		{"https://user@example.com/check", "https://user@example.com/check"},
		{"https://example.com/check?token=abc&b=&flag", "https://example.com/check?token=xxxxx&b=xxxxx&flag"},
		{"http://u:p@example.com:8080/x?key=v1&key=v2#frag", "http://u:xxxxx@example.com:8080/x?key=xxxxx&key=xxxxx#frag"},
		{"http://example.com/%zz", "<unparsable url>"},
	} {
		require.Equal(t, tc.want, redactURLForLog(tc.in), tc.in)
	}
}

// The URL kept for the check itself is the one given, secrets included.
func TestHealthCheckKeepsRawURL(t *testing.T) {
	raw := "https://user:secret@example.com/check?token=abc"
	hc := NewHealthCheck(nil, raw, 5000, 0, false, nil)
	require.Equal(t, raw, hc.url)
	hc.registerHealthCheckTask("https://example.com/other?token=def", nil, "", 0)
	require.Contains(t, hc.extra, "https://example.com/other?token=def")
}
