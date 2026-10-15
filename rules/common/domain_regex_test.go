package common

import (
	"testing"

	"github.com/metacubex/mihomo/common/regexp2x"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomainRegexHasMatchTimeout(t *testing.T) {
	rule, err := NewDomainRegex(`^(.+\.)?example\.com$`, "DIRECT")
	require.NoError(t, err)
	assert.Equal(t, regexp2x.MatchTimeout, rule.regex.MatchTimeout)

	matched, adapter := rule.Match(&C.Metadata{Host: "WWW.example.com"}, C.RuleMatchHelper{})
	assert.True(t, matched)
	assert.Equal(t, "DIRECT", adapter)
	matched, _ = rule.Match(&C.Metadata{Host: "example.org"}, C.RuleMatchHelper{})
	assert.False(t, matched)
}
