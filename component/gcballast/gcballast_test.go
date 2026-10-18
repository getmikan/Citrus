package gcballast

import (
	"runtime"
	"testing"

	"github.com/metacubex/mihomo/constant/features"
)

func TestActive(t *testing.T) {
	switch {
	case runtime.GOOS == "android" || runtime.GOOS == "ios":
		if Active() {
			t.Fatal("no ballast on android/ios")
		}
	case features.CMFA:
		if Active() {
			t.Fatal("no ballast in the embedded app (cmfa)")
		}
	}
}
