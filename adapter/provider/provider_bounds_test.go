package provider

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOverrideExprStreamCap(t *testing.T) {
	ints := func(n int) []any {
		values := make([]any, n)
		for i := range values {
			values[i] = i
		}
		return values
	}

	small := map[string]any{"name": "n", "a": ints(3), "b": ints(3)}
	override := overrideSchema{OverrideExpr: mustOverrideExprs(t, `.x = [.a[] + .b[]]`)}
	require.NoError(t, override.Apply(small))
	require.Len(t, small["x"], 9)

	// 300 x 300 = 90000 results, over the cap.
	big := map[string]any{"name": "n", "a": ints(300), "b": ints(300)}
	err := override.Apply(big)
	require.ErrorContains(t, err, "more than")
	require.NotContains(t, big, "x")

	// Unions add up too.
	union := map[string]any{"name": "n", "a": ints(40000)}
	override = overrideSchema{OverrideExpr: mustOverrideExprs(t, `.x = [.a[], .a[]]`)}
	require.ErrorContains(t, override.Apply(union), "more than")
}

func TestOverrideExprRepeatByteCap(t *testing.T) {
	mapping := map[string]any{"name": "n"}
	override := overrideSchema{OverrideExpr: mustOverrideExprs(t, `.s = "abcd" * 1000`)}
	require.NoError(t, override.Apply(mapping))
	require.Len(t, mapping["s"], 4000)

	override = overrideSchema{OverrideExpr: mustOverrideExprs(t, `.s = "abcd" * 10000000`)}
	require.ErrorContains(t, override.Apply(mapping), "exceed")
}

func providerDoc(n int) []byte {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "  - {name: p%d, type: socks5, server: 127.0.0.1, port: 1080}\n", i)
	}
	return []byte(b.String())
}

func TestProviderProxyCap(t *testing.T) {
	parse, err := NewProxiesParser("test", nil, "", "", "", "", overrideSchema{}, "")
	require.NoError(t, err)

	proxies, err := parse(providerDoc(10))
	require.NoError(t, err)
	require.Len(t, proxies, 10)

	_, err = parse(providerDoc(maxProviderEntries + 1))
	require.ErrorContains(t, err, "limit")

	_, err = parse(providerDoc(maxProviderProxies + 1))
	require.ErrorContains(t, err, "more than")

	// Filtered out entries do not count against the adapter cap.
	parse, err = NewProxiesParser("test", nil, "^p1$", "", "", "", overrideSchema{}, "")
	require.NoError(t, err)
	proxies, err = parse(providerDoc(maxProviderProxies + 1))
	require.NoError(t, err)
	require.Len(t, proxies, 1)
}
