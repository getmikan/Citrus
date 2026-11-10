package gcballast

import (
	"runtime"
	"testing"

	"github.com/metacubex/mihomo/constant/features"
)

func TestActive(t *testing.T) {
	switch {
	case runtime.GOOS != "linux":
		if Active() {
			t.Fatalf("no ballast on %s", runtime.GOOS)
		}
	case features.CMFA:
		if Active() {
			t.Fatal("no ballast in the embedded app (cmfa)")
		}
	}
}
