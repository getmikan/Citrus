package adapter

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"runtime"
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
		"split-wait":   {"split": "2", "split-wait": "soon"},
		"wait timeout": {"split": "2", "split-wait-timeout": 100},
		"disorder":     {"tlsrec": "1+s", "disorder": true},
		"oob-byte":     {"split": "2", "oob": true, "oob-byte": "ab"},
		"random":       {"random": map[string]any{"seed": 1}},
		"random range": {"random": map[string]any{"split": []any{map[string]any{"from": 9, "to": 3}}}},
		"random to":    {"random": map[string]any{"split": []any{map[string]any{"from": 1}}}},
		"random list":  {"random": map[string]any{"split": map[string]any{"from": 1, "to": 3}}},
		"fake no ttl":  {"tlsrec": "1+s", "fake": map[string]any{"prefix": -1}},
		"fake sni":     {"tlsrec": "1+s", "fake": map[string]any{"ttl": 4, "sni": "www.example.com"}},
		"auto-ttl":     {"tlsrec": "1+s", "fake": map[string]any{"ttl": 4, "auto-ttl": map[string]any{"min": 9, "max": 4}}},
		"udp template": {"udp": map[string]any{"ttl": 4, "template": "quic-v2"}},
		"udp sni":      {"udp": map[string]any{"ttl": 4, "sni": "www.example.com"}},
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

// The socket methods and random cuts as a YAML configuration decodes them.
func TestParseDesyncMethods(t *testing.T) {
	caps := desync.PlatformCapabilities()
	mapping := map[string]any{
		"name":               "desync-methods",
		"type":               "desync",
		"tlsrec":             "1+s",
		"split":              "2,1+s",
		"split-wait":         "acked",
		"split-wait-timeout": 500,
		"oob":                true,
		"oob-byte":           "z",
		"random": map[string]any{
			"tlsrec": []any{map[string]any{"from": "-8+s", "to": "8+s", "count": 2, "min-piece": 2}},
			"split":  []any{map[string]any{"from": 1, "to": 120}},
			"seed":   12345,
		},
	}
	p, err := ParseProxy(mapping)
	if !caps.OOB || !caps.Ack.Acked {
		require.Error(t, err)
		assert.Contains(t, err.Error(), runtime.GOOS)
		return
	}
	require.NoError(t, err)
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	var v struct {
		Desync struct {
			TCP map[string]json.RawMessage `json:"tcp"`
		} `json:"desync"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	tcp := v.Desync.TCP
	assert.JSONEq(t, `"acked"`, string(tcp["split-wait"]))
	assert.JSONEq(t, `500`, string(tcp["split-wait-timeout"]))
	assert.JSONEq(t, `false`, string(tcp["disorder"]))
	assert.JSONEq(t, `{"byte":"z"}`, string(tcp["oob"]))
	assert.JSONEq(t, `{"seed":12345,
		"tlsrec":[{"from":"-8+s","to":"8+s","count":2,"min-piece":2}],
		"split":[{"from":"1","to":"120","count":1,"min-piece":1}]}`, string(tcp["random"]))

	// disorder cannot wait for acknowledgement; with sent it can
	mapping["disorder"] = true
	_, err = ParseProxy(mapping)
	assert.ErrorContains(t, err, "SplitWaitAcked")
	mapping["split-wait"] = "sent"
	_, err = ParseProxy(mapping)
	if caps.Ack.Sent && caps.Disorder.Supported {
		assert.NoError(t, err)
	} else {
		assert.ErrorContains(t, err, runtime.GOOS)
	}
}

func TestParseDesyncFakeDecoy(t *testing.T) {
	p, err := ParseProxy(map[string]any{
		"name": "desync-fake", "type": "desync", "split": "1+s", "disorder": true,
		"fake": map[string]any{
			"ttl":           5,
			"auto-ttl":      map[string]any{}, // the defaults
			"prefix":        -1,
			"sni":           []any{"www.example.com", "cdn-##.example.net"},
			"randomize":     true,
			"from-original": true,
			"offset":        2,
		},
	})
	if !desync.SupportsFake() {
		assert.ErrorIs(t, err, desync.ErrFakeUnsupported)
		assert.ErrorContains(t, err, "fake is not supported on "+runtime.GOOS)
		return
	}
	require.NoError(t, err)
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	var v struct {
		Desync struct {
			TCP struct {
				Fake json.RawMessage `json:"fake"`
			} `json:"tcp"`
		} `json:"desync"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	assert.JSONEq(t, `{"ttl":5,"auto-ttl":{"delta":1,"min":3,"max":20},"prefix":-1,"timeout":3000,
		"sni":["www.example.com","cdn-##.example.net"],"randomize":true,"from-original":true,"offset":2,"last-ttl":null}`, string(v.Desync.TCP.Fake))
}

func TestParseDesyncUDPQUIC(t *testing.T) {
	p, err := ParseProxy(map[string]any{
		"name": "desync-quic", "type": "desync",
		"udp": map[string]any{"ttl": 4, "template": "quic", "sni": "www.example.com", "quic-only": true},
	})
	if !desync.SupportsUDPFake() {
		assert.ErrorIs(t, err, desync.ErrUDPFakeUnsupported)
		return
	}
	require.NoError(t, err)
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	var v struct {
		Desync struct {
			UDP map[string]any `json:"udp"`
		} `json:"desync"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	assert.Equal(t, "quic", v.Desync.UDP["template"])
	assert.Equal(t, "www.example.com", v.Desync.UDP["sni"])
	assert.Equal(t, true, v.Desync.UDP["quic-only"])
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
