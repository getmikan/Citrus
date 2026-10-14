package provider

import (
	"sync"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// TestStrategySwapIsAtomic runs refreshes against live matching; run it with
// -race to check that readers and the refresh do not share unsynchronized state.
func TestStrategySwapIsAtomic(t *testing.T) {
	bp := &baseProvider{behavior: P.Domain}
	if bp.Count() != 0 || bp.Match(&C.Metadata{Host: "example.com"}, C.RuleMatchHelper{}) {
		t.Fatal("empty provider matched")
	}

	build := func(host string) ruleStrategy {
		s := NewDomainStrategy()
		s.Insert(host)
		s.FinishInsert()
		return s
	}
	bp.setStrategy(build("example.com"))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			bp.setStrategy(build("example.com"))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			if !bp.Match(&C.Metadata{Host: "example.com"}, C.RuleMatchHelper{}) {
				t.Error("lost the match during a refresh")
				return
			}
			_ = bp.Count()
			_ = bp.Strategy()
		}
	}()
	wg.Wait()
}
