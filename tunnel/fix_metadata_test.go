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
