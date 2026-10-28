package tunnel

import (
	"net/netip"
	"testing"

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
