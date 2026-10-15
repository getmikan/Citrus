package regexp2x

import (
	"strings"
	"testing"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompileSetsMatchTimeout(t *testing.T) {
	re, err := Compile(`^(.+\.)?example\.com$`, regexp2.IgnoreCase)
	require.NoError(t, err)
	assert.Equal(t, MatchTimeout, re.MatchTimeout)
	assert.True(t, MatchString(re, "www.Example.com"))
	assert.False(t, MatchString(re, "example.org"))

	assert.Equal(t, MatchTimeout, MustCompile(`a`, regexp2.None).MatchTimeout)

	_, err = Compile(`(`, regexp2.None)
	assert.Error(t, err)
}

func TestMatchTimeoutIsNoMatch(t *testing.T) {
	// nested quantifiers backtrack exponentially on a near-miss input
	re := MustCompile(`^(a+)+$`, regexp2.None)
	input := strings.Repeat("a", 40) + "b"

	start := time.Now()
	assert.False(t, MatchString(re, input))
	assert.Less(t, time.Since(start), 5*time.Second)
	// logged once, still no match on the next call
	assert.False(t, MatchString(re, input))
}

func TestSetTimeout(t *testing.T) {
	re := regexp2.MustCompile(`a`, regexp2.None)
	SetTimeout(re)
	assert.Equal(t, MatchTimeout, re.MatchTimeout)
	SetTimeout(nil)
}
