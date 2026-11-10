package sing_tun

import (
	"net/netip"
	"testing"

	LC "github.com/metacubex/mihomo/listener/config"

	tun "github.com/metacubex/sing-tun"
	"github.com/stretchr/testify/require"
)

func TestDefaultDNSMode(t *testing.T) {
	p4 := []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}
	p4Only := []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")}
	p6 := []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")}

	for _, tc := range []struct {
		name string
		goos string
		opts LC.Tun
		want string
	}{
		{"linux manual routing keeps systemd-resolved", "linux", LC.Tun{Inet4Address: p4}, tun.DNSModeNative},
		{"linux manual routing ipv6 only", "linux", LC.Tun{Inet6Address: p6}, tun.DNSModeNative},
		{"linux manual routing without a dns address", "linux", LC.Tun{Inet4Address: p4Only}, ""},
		{"linux auto-route left to sing-tun", "linux", LC.Tun{Inet4Address: p4, AutoRoute: true}, ""},
		{"explicit mode wins", "linux", LC.Tun{Inet4Address: p4, DNSMode: tun.DNSModeDisabled}, tun.DNSModeDisabled},
		{"android unchanged", "android", LC.Tun{Inet4Address: p4}, ""},
		{"windows unchanged", "windows", LC.Tun{Inet4Address: p4}, ""},
		{"darwin unchanged", "darwin", LC.Tun{Inet4Address: p4}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, defaultDNSMode(tc.goos, tc.opts))
		})
	}
}
