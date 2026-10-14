package logic_test

import (
	"strings"
	"testing"

	. "github.com/metacubex/mihomo/rules/logic"

	"github.com/stretchr/testify/assert"
)

// nestedNOT builds the payload ((NOT,((NOT,((DOMAIN,a.com)))))) with depth
// nested NOT rules.
func nestedNOT(depth int) string {
	payload := "((DOMAIN,a.com))"
	for i := 0; i < depth; i++ {
		payload = "((NOT," + payload + "))"
	}
	return payload
}

func TestLogicDepthLimit(t *testing.T) {
	_, err := NewNOT(nestedNOT(4), "DIRECT", ParseRule)
	assert.NoError(t, err)

	_, err = NewNOT(nestedNOT(1000), "DIRECT", ParseRule)
	assert.ErrorContains(t, err, "deeper")
}

func TestLogicGroupLimit(t *testing.T) {
	groups := make([]string, 5000)
	for i := range groups {
		groups[i] = "(NETWORK,TCP)"
	}
	_, err := NewAND("("+strings.Join(groups, ",")+")", "DIRECT", ParseRule)
	assert.ErrorContains(t, err, "groups")

	_, err = NewAND("("+strings.Join(groups[:100], ",")+")", "DIRECT", ParseRule)
	assert.NoError(t, err)
}
