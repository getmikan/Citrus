package tunnel

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"
)

func TestFixMetadataNormalizesHost(t *testing.T) {
	suffix := RC.NewDomainSuffix("blocked.com", "REJECT")
	keyword := RC.NewDomainKeyword("blocked", "REJECT")
	for _, host := range []string{"WWW.Blocked.COM", "www.blocked.com.", "WWW.BLOCKED.COM."} {
		metadata := &C.Metadata{Host: host}
		fixMetadata(metadata)
		if metadata.Host != "www.blocked.com" {
			t.Fatalf("%q: host = %q", host, metadata.Host)
		}
		if ok, _ := suffix.Match(metadata, C.RuleMatchHelper{}); !ok {
			t.Errorf("%q: DOMAIN-SUFFIX did not match", host)
		}
		if ok, _ := keyword.Match(metadata, C.RuleMatchHelper{}); !ok {
			t.Errorf("%q: DOMAIN-KEYWORD did not match", host)
		}
	}

	// an IP written with a root dot still becomes the destination IP
	metadata := &C.Metadata{Host: "192.0.2.1."}
	fixMetadata(metadata)
	if metadata.Host != "" || metadata.DstIP != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("ip host: got host %q, ip %s", metadata.Host, metadata.DstIP)
	}
}

// An IPv6 zone names an interface of this host, which the user of a server
// inbound (or of a listener with egress-guard: true) has no business naming:
// it is dropped, so the guard, the loopback detector, the NAT table and the
// statistics see one spelling of the address. A local client keeps it: it
// may name an interface of its own host.
func TestFixMetadataDropsZoneOfRemoteUsers(t *testing.T) {
	for _, metadata := range []*C.Metadata{
		{Type: C.VLESS, Host: "2001:db8::1%x"},
		{Type: C.TROJAN, DstIP: netip.MustParseAddr("2001:db8::1%eth0")},
		{Type: C.HYSTERIA2, Host: "2001:db8::1%1"},
		{Type: C.VLESS, EgressGuard: C.EgressGuardOff, Host: "2001:db8::1%x"},
		{Type: C.SOCKS5, EgressGuard: C.EgressGuardOn, Host: "2001:db8::1%x"},
	} {
		typ := metadata.Type
		fixMetadata(metadata)
		if metadata.Host != "" || metadata.DstIP != netip.MustParseAddr("2001:db8::1") {
			t.Errorf("%s: got host %q, ip %s", typ, metadata.Host, metadata.DstIP)
		}
	}

	local := &C.Metadata{Type: C.SOCKS5, Host: "fe80::1%eth0"}
	fixMetadata(local)
	if local.DstIP != netip.MustParseAddr("fe80::1%eth0") {
		t.Errorf("local client: ip %s, want the zone kept", local.DstIP)
	}
}

// mappingEnhancer is a redir-host mapper that remembers one query name exactly
// as the client spelled it.
type mappingEnhancer struct {
	resolver.Enhancer
	ip   netip.Addr
	host string
}

func (*mappingEnhancer) MappingEnabled() bool     { return true }
func (*mappingEnhancer) IsFakeIP(netip.Addr) bool { return false }
func (m *mappingEnhancer) FindHostByIP(ip netip.Addr) (string, bool) {
	return m.host, ip == m.ip
}

func TestPreHandleMetadataNormalizesMappedHost(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.7")
	orig := resolver.DefaultHostMapper
	resolver.DefaultHostMapper = &mappingEnhancer{ip: ip, host: "WWW.Blocked.COM"}
	t.Cleanup(func() { resolver.DefaultHostMapper = orig })

	metadata := &C.Metadata{DstIP: ip}
	fixMetadata(metadata)
	if err := preHandleMetadata(metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Host != "www.blocked.com" {
		t.Fatalf("host = %q", metadata.Host)
	}
	suffix := RC.NewDomainSuffix("blocked.com", "REJECT")
	if ok, _ := suffix.Match(metadata, C.RuleMatchHelper{}); !ok {
		t.Error("DOMAIN-SUFFIX did not match the mapped host")
	}
}
