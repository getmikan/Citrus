package constant

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserAgent(t *testing.T) {
	ua := UserAgent()
	assert.True(t, strings.HasPrefix(ua, "clash.meta/"+Version+" "), ua)
	assert.Contains(t, ua, " citrus/"+Version)
}
