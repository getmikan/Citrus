package adapter

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/Nemu-x/desync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDesync(t *testing.T) {
	p, err := ParseProxy(map[string]any{
		"name":           "desync-yt",
		"type":           "desync",
		"tlsrec":         "1+s",
		"split":          2, // a YAML number is a single position
		"split-delay":    5,
		"interface-name": "",
		"routing-mark":   0,
		"ip-version":     "ipv4-prefer",
	})
	require.NoError(t, err)
	assert.Equal(t, "desync-yt", p.Name())
	assert.Equal(t, C.Desync, p.Type())
	assert.Equal(t, "Desync", p.Type().String())
	assert.True(t, p.SupportUDP())

	raw, err := json.Marshal(p)
	require.NoError(t, err)
	var v map[string]any
	require.NoError(t, json.Unmarshal(raw, &v))
	assert.Equal(t, "Desync", v["type"])
	assert.Equal(t, "desync-yt", v["name"])
	assert.Equal(t, true, v["udp"], "UDP is supported, plain without udp options")
	info, _ := v["desync"].(map[string]any)
	assert.Equal(t, "static", info["strategy"])
	tcp, _ := info["tcp"].(map[string]any)
	assert.Equal(t, []any{"1+s"}, tcp["tlsrec"])
	assert.Equal(t, []any{"2"}, tcp["split"])
	assert.EqualValues(t, 5, tcp["split-delay"])
	assert.Contains(t, info, "udp")
	assert.Nil(t, info["udp"])
}

func TestParseDesyncInvalid(t *testing.T) {
	for name, extra := range map[string]map[string]any{
		"no method":    {},
		"bad position": {"tlsrec": "1+x"},
		"long delay":   {"split": "2", "split-delay": 5000},
		"tfo":          {"tlsrec": "1+s", "tfo": true},
		"mptcp":        {"tlsrec": "1+s", "mptcp": true},
		"dialer-proxy": {"tlsrec": "1+s", "dialer-proxy": "vpn"},
		"fake ttl":     {"tlsrec": "1+s", "fake": map[string]any{"ttl": 999}},
		"udp repeats":  {"udp": map[string]any{"ttl": 4, "repeats": 100}},
	} {
		mapping := map[string]any{"name": name, "type": "desync"}
		for k, v := range extra {
			mapping[k] = v
		}
		_, err := ParseProxy(mapping)
		assert.Error(t, err, name)
	}
}

func TestParseDesyncPlatformMethods(t *testing.T) {
	_, err := ParseProxy(map[string]any{
		"name": "fake", "type": "desync", "tlsrec": "1+s",
		"fake": map[string]any{"ttl": 4, "prefix": -1, "timeout": 3000},
	})
	if desync.SupportsFake() {
		assert.NoError(t, err)
	} else {
		assert.ErrorIs(t, err, desync.ErrFakeUnsupported)
	}
	_, err = ParseProxy(map[string]any{
		"name": "udp", "type": "desync", "tlsrec": "1+s",
		"udp": map[string]any{"ttl": 4, "repeats": 6, "packets": 3},
	})
	if desync.SupportsUDPFake() {
		assert.NoError(t, err)
	} else {
		assert.ErrorIs(t, err, desync.ErrUDPFakeUnsupported)
	}
}

// A URL test of the outbound dials through the transformer: the test
// server's raw socket receives a fragmented ClientHello. The handshake
// itself fails on the self-made server, which does not matter here.
func TestDesyncURLTestGoesThroughTransformer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	records := make(chan int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			records <- -1
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		header := make([]byte, 5)
		if _, err := io.ReadFull(c, header); err != nil || header[0] != 0x16 {
			records <- -1
			return
		}
		body := make([]byte, binary.BigEndian.Uint16(header[3:]))
		if _, err := io.ReadFull(c, body); err != nil {
			records <- -1
			return
		}
		// the first record's handshake length announces more than it holds
		if len(body) < 4 || len(body) < 4+(int(body[1])<<16|int(body[2])<<8|int(body[3])) {
			records <- 2
		} else {
			records <- 1
		}
	}()

	// an IP literal sends no server name, so cut at an absolute position
	p, err := ParseProxy(map[string]any{"name": "desync-yt", "type": "desync", "tlsrec": "1+s,8"})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = p.URLTest(ctx, fmt.Sprintf("https://127.0.0.1:%d/generate_204", ln.Addr().(*net.TCPAddr).Port), nil)
	assert.Equal(t, 2, <-records, "the URL test's ClientHello was not fragmented")
}
