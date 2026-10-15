package features

import "testing"

func TestAffectedByGoIssue78041(t *testing.T) {
	for v, want := range map[string]bool{
		"go1.26rc1":                       true,
		"go1.26.0":                        true,
		"go1.26.1":                        true,
		"go1.26.1 X:nocoverageredesign":   true,
		"go1.26.2":                        false,
		"go1.26.10":                       false,
		"go1.25.8":                        false,
		"go1.27.0":                        false,
		"devel go1.27-abcdef Mon Jan 1 1": false,
	} {
		if got := AffectedByGoIssue78041(v); got != want {
			t.Errorf("AffectedByGoIssue78041(%q) = %v, want %v", v, got, want)
		}
	}
}
