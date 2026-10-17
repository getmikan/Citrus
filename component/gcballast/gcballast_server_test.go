//go:build !android && !ios

package gcballast

import (
	"os"
	"testing"

	"github.com/metacubex/mihomo/constant/features"
)

func TestWanted(t *testing.T) {
	env := func(vars map[string]string) func(string) string {
		return func(k string) string { return vars[k] }
	}
	if features.CMFA {
		if gcBallastWanted(env(nil)) {
			t.Fatal("the embedded app (cmfa) must go without the ballast")
		}
		return
	}
	if !gcBallastWanted(env(nil)) {
		t.Fatal("a server build without GOGC/GOMEMLIMIT gets the ballast")
	}
	for _, k := range []string{"GOGC", "GOMEMLIMIT"} {
		if gcBallastWanted(env(map[string]string{k: "100"})) {
			t.Fatalf("%s set: no ballast", k)
		}
	}
}

func TestActiveMatchesWanted(t *testing.T) {
	if Active() != gcBallastWanted(os.Getenv) {
		t.Fatalf("Active() = %v with this environment", Active())
	}
}
