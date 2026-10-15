package inbound_test

import (
	"runtime"
	"testing"

	"github.com/metacubex/mihomo/constant/features"
)

// TestToolchainWindowsUDP fails fast with a clear message instead of letting the
// UDP tests below (TestInboundMieru/UDP_* in particular) corrupt the stack and
// crash the whole test binary with "fatal error: fault" on a broken toolchain.
func TestToolchainWindowsUDP(t *testing.T) {
	if features.AffectedByGoIssue78041(runtime.Version()) {
		t.Fatalf("%s has the Windows UDP stack corruption bug (https://go.dev/issue/78041): "+
			"UDP tests will crash the runtime at random; build and test with go1.26.2 or newer", runtime.Version())
	}
}
