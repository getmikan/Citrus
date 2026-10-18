package v5

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A domain of 255 bytes, the longest the address can carry: its length
// byte plus one overflowed a byte, and the server panicked on the CONNECT.
func TestReadAddressLongestDomain(t *testing.T) {
	for _, n := range []int{1, 254, 255} {
		host := strings.Repeat("a", n)
		var b bytes.Buffer
		require.NoError(t, NewConnect(NewAddress(&C.Metadata{Host: host, DstPort: 443})).WriteTo(&b))
		connect, err := ReadConnect(bufio.NewReader(&b))
		require.NoError(t, err, n)
		assert.Equal(t, host, string(connect.ADDR.ADDR[1:]), n)
		assert.Equal(t, uint16(443), connect.ADDR.PORT, n)
	}
}
