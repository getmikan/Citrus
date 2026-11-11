package tunnel

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"

	"github.com/stretchr/testify/assert"
)

type rejectProxy struct{ namedProxy }

func (rejectProxy) Type() C.AdapterType { return C.Reject }

// processRule matches by process name, looking the process up the way the
// PROCESS-NAME rule does.
type processRule struct {
	RC.Base
	name string
}

func (r *processRule) RuleType() C.RuleType { return C.ProcessName }
func (r *processRule) Adapter() string      { return "REJECT" }
func (r *processRule) Payload() string      { return r.name }
func (r *processRule) Match(md *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if helper.FindProcess != nil {
		helper.FindProcess()
	}
	return md.Process == r.name, "REJECT"
}

func TestProtocolVerdictReusesSessionProcess(t *testing.T) {
	setupReplaceRules(t)
	UpdateProxies(map[string]C.Proxy{
		"DIRECT": namedProxy{name: "DIRECT"},
		"REJECT": rejectProxy{namedProxy{name: "REJECT"}},
	}, nil)
	UpdateRules([]C.Rule{&processRule{name: "bt.exe"}}, nil, nil)
	oldMode := FindProcessMode()
	SetFindProcessMode(process.FindProcessStrict)
	lookups := 0
	oldFind := findProcessName
	findProcessName = func(string, netip.Addr, int) (uint32, string, error) {
		lookups++
		return 0, "/apps/bt.exe", nil
	}
	t.Cleanup(func() {
		findProcessName = oldFind
		SetFindProcessMode(oldMode)
	})

	verdict := newProtocolVerdict()
	for i := 1; i <= 3; i++ {
		metadata := &C.Metadata{
			NetWork:       C.UDP,
			Type:          C.TUN,
			SrcIP:         netip.MustParseAddr("192.168.1.10"),
			SrcPort:       6881,
			DstIP:         netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}),
			DstPort:       6881,
			SniffProtocol: "bittorrent",
		}
		assert.True(t, verdict(metadata), "destination %d", i)
		assert.Equal(t, "bt.exe", metadata.Process)
	}
	assert.Equal(t, 1, lookups, "the process is looked up once per session")

	// another session looks its own process up
	other := &C.Metadata{NetWork: C.UDP, Type: C.TUN, SrcIP: netip.MustParseAddr("192.168.1.11"), SrcPort: 6881,
		DstIP: netip.MustParseAddr("198.51.100.9"), DstPort: 6881, SniffProtocol: "bittorrent"}
	assert.True(t, newProtocolVerdict()(other))
	assert.Equal(t, 2, lookups)
}
