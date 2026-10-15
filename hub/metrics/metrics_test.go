package metrics

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	metricNameRe = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	labelNameRe  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

// parseExposition validates a text exposition (version 0.0.4) and returns its
// samples keyed by `name{label="value",...}` with the labels in the order
// written. It checks that every family has one HELP and one TYPE line before
// its samples, that the samples of a family are contiguous, that the names,
// the label syntax and escaping, and the values are valid, that counters end
// with _total, and that histogram buckets are cumulative and end with +Inf.
func parseExposition(t *testing.T, text string) map[string]float64 {
	t.Helper()
	samples := map[string]float64{}
	types := map[string]string{}
	helps := map[string]bool{}
	done := map[string]bool{}
	current := ""
	var lastBucket float64
	var sawInf bool

	familyOf := func(name string) string {
		for _, suffix := range []string{"_bucket", "_sum", "_count"} {
			if base := strings.TrimSuffix(name, suffix); base != name && types[base] == "histogram" {
				return base
			}
		}
		return name
	}

	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		l := sc.Text()
		require.NotEmpty(t, l, "line %d: empty line", line)
		if strings.HasPrefix(l, "# ") {
			f := strings.SplitN(l, " ", 4)
			require.GreaterOrEqual(t, len(f), 4, "line %d: %q", line, l)
			name := f[2]
			require.Regexp(t, metricNameRe, name, "line %d", line)
			require.False(t, done[name], "line %d: family %s is not contiguous", line, name)
			switch f[1] {
			case "HELP":
				require.False(t, helps[name], "line %d: second HELP of %s", line, name)
				helps[name] = true
				require.NotContains(t, f[3], "\n")
			case "TYPE":
				require.True(t, helps[name], "line %d: TYPE of %s before HELP", line, name)
				require.Empty(t, types[name], "line %d: second TYPE of %s", line, name)
				require.Contains(t, []string{"counter", "gauge", "histogram", "summary", "untyped"}, f[3], "line %d", line)
				types[name] = f[3]
				if f[3] == "counter" {
					require.True(t, strings.HasSuffix(name, "_total"), "counter %s must end with _total", name)
				}
			default:
				t.Fatalf("line %d: unknown comment %q", line, l)
			}
			if current != "" && current != name {
				done[current] = true
			}
			if current != name {
				lastBucket, sawInf = 0, false
			}
			current = name
			continue
		}

		// a sample: name, optional labels, a space, the value
		i := strings.IndexAny(l, "{ ")
		require.Greater(t, i, 0, "line %d: %q", line, l)
		name := l[:i]
		require.Regexp(t, metricNameRe, name, "line %d", line)
		family := familyOf(name)
		require.Equal(t, current, family, "line %d: sample of %s outside its family", line, name)
		require.NotEmpty(t, types[family], "line %d: sample without TYPE", line)
		rest := l[i:]
		key := name
		var le string
		if rest[0] == '{' {
			var labels []string
			j := 1
			for rest[j] != '}' {
				eq := strings.IndexByte(rest[j:], '=')
				require.Greater(t, eq, 0, "line %d: label without =", line)
				lname := rest[j : j+eq]
				require.Regexp(t, labelNameRe, lname, "line %d", line)
				j += eq + 1
				require.Equal(t, byte('"'), rest[j], "line %d: unquoted label value", line)
				j++
				var value strings.Builder
				for rest[j] != '"' {
					c := rest[j]
					if c == '\\' {
						j++
						switch rest[j] {
						case '\\', '"':
							value.WriteByte(rest[j])
						case 'n':
							value.WriteByte('\n')
						default:
							t.Fatalf("line %d: bad escape \\%c", line, rest[j])
						}
					} else {
						value.WriteByte(c)
					}
					j++
				}
				j++
				if lname == "le" {
					le = value.String()
				}
				labels = append(labels, fmt.Sprintf("%s=%q", lname, value.String()))
				if rest[j] == ',' {
					j++
				}
			}
			key += "{" + strings.Join(labels, ",") + "}"
			rest = rest[j+1:]
		}
		require.True(t, strings.HasPrefix(rest, " "), "line %d: no space before the value", line)
		v, err := strconv.ParseFloat(strings.TrimPrefix(rest[1:], "+"), 64)
		require.NoError(t, err, "line %d: value %q", line, rest)
		_, dup := samples[key]
		require.False(t, dup, "line %d: duplicate series %s", line, key)
		samples[key] = v

		if types[family] == "histogram" && strings.HasSuffix(name, "_bucket") {
			require.NotEmpty(t, le, "line %d: bucket without le", line)
			require.GreaterOrEqual(t, v, lastBucket, "line %d: buckets are not cumulative", line)
			lastBucket = v
			if le == "+Inf" {
				sawInf = true
			}
		}
		if types[family] == "histogram" && strings.HasSuffix(name, "_count") {
			require.True(t, sawInf, "histogram %s without a +Inf bucket", family)
			require.Equal(t, lastBucket, v, "histogram %s: _count differs from the +Inf bucket", family)
		}
	}
	require.NoError(t, sc.Err())
	for name := range helps {
		require.NotEmpty(t, types[name], "family %s without TYPE", name)
	}
	return samples
}

func render(t *testing.T, o Options) (string, map[string]float64) {
	t.Helper()
	var b bytes.Buffer
	require.NoError(t, Write(&b, o))
	return b.String(), parseExposition(t, b.String())
}

func TestWriterEscaping(t *testing.T) {
	var b bytes.Buffer
	bw := bufio.NewWriter(&b)
	w := newWriter(bw)
	w.family("x_total", "counter", "a \\ help\nline")
	w.int("x_total", 3, "user", "a\"b\\c\nd", "inbound", "in")
	w.float("y", 0.5)
	require.NoError(t, bw.Flush())
	assert.Equal(t, "# HELP x_total a \\\\ help\\nline\n# TYPE x_total counter\n"+
		`x_total{user="a\"b\\c\nd",inbound="in"} 3`+"\ny 0.5\n", b.String())
	assert.Equal(t, "+Inf", formatFloat(posInf()))
}

func posInf() float64 { v, _ := strconv.ParseFloat("+Inf", 64); return v }

// pipeTracker returns a tracker of a connection of inbound and user, and the
// other end of its pipe.
type trackedConn interface {
	statistic.Tracker
	io.ReadWriter
}

func pipeTracker(t *testing.T, inbound, user string) (trackedConn, net.Conn) {
	local, remote := net.Pipe()
	t.Cleanup(func() { _ = remote.Close() })
	metadata := &C.Metadata{
		NetWork: C.TCP, Type: C.INNER,
		SrcIP: netip.MustParseAddr("192.0.2.10"), SrcPort: 1000,
		DstIP: netip.MustParseAddr("192.0.2.20"), DstPort: 80,
		InName: inbound, InUser: user,
	}
	tr := statistic.NewTCPTracker(outbound.NewConn(local, outbound.NewDirect()), statistic.DefaultManager, metadata, nil, 0, 0, true)
	return tr, remote
}

// exchange sends up bytes through the tracker and receives down bytes.
func exchange(t *testing.T, tr trackedConn, remote net.Conn, up, down int) {
	go func() {
		_, _ = io.CopyN(io.Discard, remote, int64(up))
		_, _ = remote.Write(make([]byte, down))
	}()
	n, err := tr.Write(make([]byte, up))
	require.NoError(t, err)
	require.Equal(t, up, n)
	_, err = io.ReadFull(tr, make([]byte, down))
	require.NoError(t, err)
}

func series(name string, labels ...string) string {
	parts := make([]string, 0, len(labels)/2)
	for i := 0; i+1 < len(labels); i += 2 {
		parts = append(parts, fmt.Sprintf("%s=%q", labels[i], labels[i+1]))
	}
	if len(parts) == 0 {
		return name
	}
	return name + "{" + strings.Join(parts, ",") + "}"
}

func TestMetricsValues(t *testing.T) {
	SetOptions(Options{Enable: true, PerUser: true})
	t.Cleanup(func() { SetOptions(Options{}) })
	// the counters are global: a fresh inbound keeps -count=N runs apart
	in := "metrics-in-" + utils.NewUUIDV4().String()

	_, before := render(t, Current())
	opened := before["citrus_connections_opened_total"]
	upTotal := before[series("citrus_traffic_bytes_total", "direction", "up")]

	alice, aliceRemote := pipeTracker(t, in, "alice")
	bob, bobRemote := pipeTracker(t, in, "bob")
	exchange(t, alice, aliceRemote, 100, 1000)
	exchange(t, bob, bobRemote, 7, 70)
	defer bob.Close()

	text, s := render(t, Current())
	assert.Contains(t, text, `citrus_build_info{version="`)
	assert.Equal(t, boolF(tunnel.Status() == tunnel.Running), s["citrus_live"])
	assert.GreaterOrEqual(t, s["citrus_connections_opened_total"]-opened, float64(2))
	assert.GreaterOrEqual(t, s[series("citrus_traffic_bytes_total", "direction", "up")]-upTotal, float64(107))
	assert.GreaterOrEqual(t, s["citrus_connections"], float64(2))
	assert.Greater(t, s["citrus_goroutines"], float64(0))
	assert.Greater(t, s["citrus_heap_bytes"], float64(0))
	assert.Contains(t, s, series("citrus_gc_pause_seconds_bucket", "le", "+Inf"))

	assert.Equal(t, float64(2), s[series("citrus_inbound_connections", "inbound", in)])
	assert.Equal(t, float64(107), s[series("citrus_inbound_traffic_bytes_total", "inbound", in, "direction", "up")])
	assert.Equal(t, float64(1070), s[series("citrus_inbound_traffic_bytes_total", "inbound", in, "direction", "down")])

	assert.Equal(t, float64(100), s[series("citrus_user_traffic_bytes_total", "inbound", in, "user", "alice", "direction", "up")])
	assert.Equal(t, float64(1000), s[series("citrus_user_traffic_bytes_total", "inbound", in, "user", "alice", "direction", "down")])
	assert.Equal(t, float64(1), s[series("citrus_user_connections", "inbound", in, "user", "alice")])
	assert.Equal(t, float64(1), s[series("citrus_user_online_ips", "inbound", in, "user", "alice")])

	// a drain (GET /traffic/users?reset=true) does not touch the cumulative series
	statistic.DefaultManager.Users().DrainFunc(func(k statistic.UserKey) bool { return k.Inbound == in })
	require.NoError(t, alice.Close())
	_, s = render(t, Current())
	assert.Equal(t, float64(100), s[series("citrus_user_traffic_bytes_total", "inbound", in, "user", "alice", "direction", "up")])
	assert.Equal(t, float64(0), s[series("citrus_user_connections", "inbound", in, "user", "alice")])
	assert.Equal(t, float64(1), s[series("citrus_user_online_ips", "inbound", in, "user", "alice")], "within the release window")
	assert.Equal(t, float64(1), s[series("citrus_inbound_connections", "inbound", in)])
	assert.Equal(t, float64(1070), s[series("citrus_inbound_traffic_bytes_total", "inbound", in, "direction", "down")])
}

func boolF(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func TestMetricsPerUserToggle(t *testing.T) {
	SetOptions(Options{Enable: true})
	t.Cleanup(func() { SetOptions(Options{}) })
	in := "metrics-toggle-" + utils.NewUUIDV4().String()
	tr, remote := pipeTracker(t, in, "carol")
	defer tr.Close()
	exchange(t, tr, remote, 1, 1)

	text, s := render(t, Current())
	assert.NotContains(t, text, "citrus_user_")
	assert.NotContains(t, text, "citrus_users ")
	assert.Equal(t, float64(1), s[series("citrus_inbound_connections", "inbound", in)])

	text, s = render(t, Options{Enable: true, PerUser: true})
	assert.Contains(t, text, "citrus_user_traffic_bytes_total")
	assert.Equal(t, float64(1), s[series("citrus_user_connections", "inbound", in, "user", "carol")])
}

func TestMetricsInboundOnlyWhileEnabled(t *testing.T) {
	SetOptions(Options{})
	in := "metrics-off-" + utils.NewUUIDV4().String()
	tr, remote := pipeTracker(t, in, "dave")
	defer tr.Close()
	exchange(t, tr, remote, 5, 5)
	text, _ := render(t, Options{Enable: true})
	assert.NotContains(t, text, in, "a connection opened while the metrics were off is not counted per inbound")
}

func TestMetricsRejected(t *testing.T) {
	SetOptions(Options{Enable: true, PerUser: true})
	t.Cleanup(func() { SetOptions(Options{}) })
	in := "metrics-rej-" + utils.NewUUIDV4().String()
	um := statistic.DefaultManager.Users()
	key := statistic.UserKey{Inbound: in, User: "eve"}
	require.NoError(t, um.SetLimit(statistic.UserLimit{Inbound: in, User: "eve", MaxConns: 1}))
	defer um.DeleteLimit(key)
	ip := netip.MustParseAddr("192.0.2.30")
	c, err := um.Admit(key, ip)
	require.NoError(t, err)
	defer um.Release(c, ip)
	for i := 0; i < 3; i++ {
		_, err = um.Admit(key, ip)
		require.Error(t, err)
	}
	_, s := render(t, Current())
	assert.Equal(t, float64(3), s[series("citrus_user_rejected_total", "inbound", in, "user", "eve", "reason", statistic.RejectMaxConns)])
}

func TestProbes(t *testing.T) {
	prev := tunnel.Status()
	t.Cleanup(func() {
		switch prev {
		case tunnel.Running:
			tunnel.OnRunning()
		case tunnel.Inner:
			tunnel.OnInnerLoading()
		default:
			tunnel.OnSuspend()
		}
	})
	tunnel.OnSuspend()
	ok, reason := Live()
	assert.False(t, ok)
	assert.Equal(t, "suspend", reason)
	ok, _ = Ready()
	assert.False(t, ok)
	tunnel.OnInnerLoading()
	ok, _ = Live()
	assert.False(t, ok)
	tunnel.OnRunning()
	ok, _ = Live()
	assert.True(t, ok)
	ok, _ = Ready()
	assert.True(t, ok)
}

func TestMemoryLimit(t *testing.T) {
	original := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(original) })

	debug.SetMemoryLimit(math.MaxInt64)
	assert.Equal(t, uint64(0), MemoryLimit(), "unlimited")
	_, s := render(t, Options{Enable: true})
	assert.Equal(t, float64(0), s["citrus_memory_limit_bytes"])

	debug.SetMemoryLimit(64 << 20)
	assert.Equal(t, uint64(64<<20), MemoryLimit())
	assert.Equal(t, int64(64<<20), debug.SetMemoryLimit(-1), "reading does not change the limit")
	_, s = render(t, Options{Enable: true})
	assert.Equal(t, float64(64<<20), s["citrus_memory_limit_bytes"])
}
