package common

import (
	"strconv"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInUserList(t *testing.T) {
	r, err := NewInUser("alice/ bob /carol", "REJECT")
	require.NoError(t, err)
	assert.Equal(t, "alice/ bob /carol", r.Payload())
	for user, want := range map[string]bool{"alice": true, "bob": true, "carol": true, "dave": false, "": false, " bob ": false} {
		ok, adapter := r.Match(&C.Metadata{InUser: user}, C.RuleMatchHelper{})
		assert.Equal(t, want, ok, user)
		if want {
			assert.Equal(t, "REJECT", adapter)
		}
	}

	for _, payload := range []string{"", "alice//bob", "alice/ "} {
		_, err := NewInUser(payload, "REJECT")
		assert.Error(t, err, payload)
	}
}

func BenchmarkInUserLongList(b *testing.B) {
	names := make([]string, 10000)
	for i := range names {
		names[i] = "user-" + strconv.Itoa(i)
	}
	r, err := NewInUser(strings.Join(names, "/"), "REJECT")
	require.NoError(b, err)
	m := &C.Metadata{InUser: "not-listed"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Match(m, C.RuleMatchHelper{})
	}
}
