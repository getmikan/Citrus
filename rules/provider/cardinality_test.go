package provider

import (
	"strings"
	"testing"

	P "github.com/metacubex/mihomo/constant/provider"
)

func TestRuleProviderCardinalityLimit(t *testing.T) {
	const limit = 3
	ok := []byte("a.example\nb.example\nc.example\n")
	strategy, err := rulesParseWithLimit(ok, NewDomainStrategy(), P.TextRule, limit)
	if err != nil || strategy.Count() != limit {
		t.Fatalf("at limit: count=%d err=%v", strategy.Count(), err)
	}

	tooMany := []byte(strings.ReplaceAll(string(ok), "c.example\n", "c.example\nd.example\n"))
	if _, err := rulesParseWithLimit(tooMany, NewDomainStrategy(), P.TextRule, limit); err == nil {
		t.Fatal("provider above the rule limit was accepted")
	}
}

func TestCompiledDomainCardinalityCount(t *testing.T) {
	strategy := NewDomainStrategy()
	for _, domain := range []string{"a.example", "b.example", "c.example"} {
		strategy.Insert(domain)
	}
	strategy.FinishInsert()
	if err := validateDomainSetEntries(strategy.domainSet, 3); err != nil {
		t.Fatalf("at compiled limit: %v", err)
	}
	if err := validateDomainSetEntries(strategy.domainSet, 2); err == nil {
		t.Fatal("compiled entries above the limit were accepted despite any declared MRS count")
	}
}
