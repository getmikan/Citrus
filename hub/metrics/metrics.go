// Package metrics renders the Prometheus metrics of the core (GET /metrics)
// and answers the health probes (GET /healthz, GET /readyz).
package metrics

import (
	"bufio"
	"io"
	"math"
	"runtime"
	"runtime/debug"
	rtmetrics "runtime/metrics"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/component/eventbus"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// Options are the `metrics` section and `health-without-auth`.
type Options struct {
	Enable            bool
	PerUser           bool
	HealthWithoutAuth bool
}

var (
	options   atomic.Pointer[Options]
	startTime = time.Now()
)

// SetOptions applies the options (on every configuration load).
func SetOptions(o Options) {
	options.Store(&o)
	statistic.SetInboundStatsEnabled(o.Enable)
}

// Current returns the options in force; all off before the first load.
func Current() Options {
	if o := options.Load(); o != nil {
		return *o
	}
	return Options{}
}

// Live reports whether the tunnel is running: false while the configuration
// is being (re)loaded, with the state as the reason.
func Live() (bool, string) {
	if s := tunnel.Status(); s != tunnel.Running {
		return false, s.String()
	}
	return true, ""
}

// Ready reports whether the configuration is applied and every listener of
// the `listeners` section listens.
func Ready() (bool, string) {
	if ok, reason := Live(); !ok {
		return false, "tunnel " + reason
	}
	if n := listener.FailedInboundListeners(); n > 0 {
		return false, "listeners failed to start"
	}
	return true, ""
}

// Write renders all the metrics in the text exposition format.
func Write(out io.Writer, o Options) error {
	bw := bufio.NewWriterSize(out, 32*1024)
	w := newWriter(bw)
	writeProcess(w)
	writeTraffic(w)
	writeInbounds(w)
	if o.PerUser {
		writeUsers(w)
	}
	writeProxies(w)
	writeChains(w)
	writeEvents(w)
	return bw.Flush()
}

// writeEvents reports the event stream (GET /events).
func writeEvents(w writer) {
	b := eventbus.Default
	w.family("citrus_event_subscribers", "gauge", "Open GET /events streams.")
	w.int("citrus_event_subscribers", int64(b.Subscribers()))
	w.family("citrus_events_published_total", "counter", "Events delivered to at least one GET /events stream, by type.")
	for i, n := range b.Published() {
		w.int("citrus_events_published_total", int64(n), "type", eventbus.Types[i])
	}
	w.family("citrus_events_dropped_total", "counter", "Events dropped for GET /events streams that read too slowly.")
	w.int("citrus_events_dropped_total", int64(b.Dropped()))
}

// runtime/metrics samples; the GC pause histogram was renamed in Go 1.22.
var (
	sampleOnce    sync.Once
	sampleNames   []string
	gcPauseMetric string
)

const (
	rmGoroutines = "/sched/goroutines:goroutines"
	rmHeap       = "/memory/classes/heap/objects:bytes"
	rmGCCycles   = "/gc/cycles/total:gc-cycles"
)

func runtimeSamples() []rtmetrics.Sample {
	sampleOnce.Do(func() {
		have := map[string]bool{}
		for _, d := range rtmetrics.All() {
			have[d.Name] = true
		}
		for _, name := range []string{rmGoroutines, rmHeap, rmGCCycles} {
			if have[name] {
				sampleNames = append(sampleNames, name)
			}
		}
		for _, name := range []string{"/sched/pauses/total/gc:seconds", "/gc/pauses:seconds"} {
			if have[name] {
				gcPauseMetric = name
				sampleNames = append(sampleNames, name)
				break
			}
		}
	})
	samples := make([]rtmetrics.Sample, len(sampleNames))
	for i, name := range sampleNames {
		samples[i].Name = name
	}
	rtmetrics.Read(samples)
	return samples
}

// MemoryLimit returns the soft memory limit the Go runtime enforces, set by
// GOMEMLIMIT or debug.SetMemoryLimit, and 0 when there is none: the runtime
// spells "unlimited" as math.MaxInt64.
func MemoryLimit() uint64 {
	// a negative argument only reads the limit
	limit := debug.SetMemoryLimit(-1)
	if limit == math.MaxInt64 || limit < 0 {
		return 0
	}
	return uint64(limit)
}

// gcPauseBuckets are the upper bounds of citrus_gc_pause_seconds.
var gcPauseBuckets = []float64{0.00001, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 1}

func writeProcess(w writer) {
	w.family("citrus_build_info", "gauge", "Build information of the core.")
	w.int("citrus_build_info", 1, "version", C.Version, "go_version", runtime.Version())

	w.family("citrus_start_time_seconds", "gauge", "Start time of the process since the unix epoch in seconds.")
	w.float("citrus_start_time_seconds", float64(startTime.UnixNano())/1e9)
	w.family("citrus_uptime_seconds", "gauge", "Seconds since the process started.")
	w.float("citrus_uptime_seconds", time.Since(startTime).Seconds())

	for _, s := range runtimeSamples() {
		switch s.Name {
		case rmGoroutines:
			w.family("citrus_goroutines", "gauge", "Number of goroutines.")
			w.int("citrus_goroutines", int64(s.Value.Uint64()))
		case rmHeap:
			w.family("citrus_heap_bytes", "gauge", "Bytes of live and not yet swept heap objects.")
			w.int("citrus_heap_bytes", int64(s.Value.Uint64()))
		case rmGCCycles:
			w.family("citrus_gc_cycles_total", "counter", "Completed GC cycles.")
			w.int("citrus_gc_cycles_total", int64(s.Value.Uint64()))
		case gcPauseMetric:
			if s.Value.Kind() == rtmetrics.KindFloat64Histogram {
				writeGCPauses(w, s.Value.Float64Histogram())
			}
		}
	}

	w.family("citrus_resident_memory_bytes", "gauge", "Resident memory of the process in bytes.")
	w.int("citrus_resident_memory_bytes", int64(statistic.DefaultManager.Memory()))
	w.family("citrus_memory_limit_bytes", "gauge", "Soft memory limit of the Go runtime (GOMEMLIMIT), 0 when unlimited.")
	w.int("citrus_memory_limit_bytes", int64(MemoryLimit()))

	if open, max, ok := openFDs(); ok {
		w.family("citrus_open_fds", "gauge", "Number of open file descriptors.")
		w.int("citrus_open_fds", open)
		if max > 0 {
			w.family("citrus_max_fds", "gauge", "Limit of open file descriptors.")
			w.int("citrus_max_fds", max)
		}
	}

	live, _ := Live()
	ready, _ := Ready()
	w.family("citrus_live", "gauge", "1 when the tunnel is running (GET /healthz).")
	w.int("citrus_live", boolValue(live))
	w.family("citrus_ready", "gauge", "1 when the configuration is applied and every listener listens (GET /readyz).")
	w.int("citrus_ready", boolValue(ready))
	w.family("citrus_listeners_failed", "gauge", "Listeners of the configuration that failed to start.")
	w.int("citrus_listeners_failed", int64(listener.FailedInboundListeners()))
}

// writeGCPauses folds the fine runtime histogram into gcPauseBuckets. A
// runtime bucket is counted in the first bucket whose bound is not below its
// upper edge; the sum is estimated from the bucket midpoints.
func writeGCPauses(w writer, h *rtmetrics.Float64Histogram) {
	counts := make([]uint64, len(gcPauseBuckets))
	var total uint64
	var sum float64
	for i, n := range h.Counts {
		if n == 0 {
			continue
		}
		lo, hi := h.Buckets[i], h.Buckets[i+1]
		total += n
		var mid float64
		switch {
		case math.IsInf(lo, -1):
			mid = hi
		case math.IsInf(hi, 1):
			mid = lo
		default:
			mid = (lo + hi) / 2
		}
		sum += mid * float64(n)
		for j, le := range gcPauseBuckets {
			if hi <= le {
				counts[j] += n
				break
			}
		}
	}
	const name = "citrus_gc_pause_seconds"
	w.family(name, "histogram", "Stop-the-world pauses of the GC (approximate, from runtime/metrics).")
	var cum uint64
	for j, le := range gcPauseBuckets {
		cum += counts[j]
		w.int(name+"_bucket", int64(cum), "le", formatFloat(le))
	}
	w.int(name+"_bucket", int64(total), "le", "+Inf")
	w.float(name+"_sum", sum)
	w.int(name+"_count", int64(total))
}

func writeTraffic(w writer) {
	m := statistic.DefaultManager
	up, down := m.Total()
	w.family("citrus_traffic_bytes_total", "counter", "Bytes carried through the tunnel since start.")
	w.int("citrus_traffic_bytes_total", up, "direction", "up")
	w.int("citrus_traffic_bytes_total", down, "direction", "down")
	w.family("citrus_connections", "gauge", "Open connections and UDP sessions.")
	w.int("citrus_connections", int64(m.ConnectionCount()))
	w.family("citrus_connections_opened_total", "counter", "Connections and UDP sessions opened since start.")
	w.int("citrus_connections_opened_total", m.ConnectionsOpened())
}

func writeInbounds(w writer) {
	stats := statistic.DefaultManager.Inbounds()
	w.family("citrus_inbound_connections", "gauge", "Open connections and UDP sessions of an inbound.")
	for _, s := range stats {
		w.int("citrus_inbound_connections", s.Conns, "inbound", s.Inbound)
	}
	w.family("citrus_inbound_traffic_bytes_total", "counter", "Bytes carried for the connections of an inbound since the metrics were enabled.")
	for _, s := range stats {
		w.int("citrus_inbound_traffic_bytes_total", s.Up, "inbound", s.Inbound, "direction", "up")
		w.int("citrus_inbound_traffic_bytes_total", s.Down, "inbound", s.Inbound, "direction", "down")
	}
}

func writeUsers(w writer) {
	users := statistic.DefaultManager.Users().Metrics()
	w.family("citrus_users", "gauge", "Users with a counter (active within the idle TTL).")
	w.int("citrus_users", int64(len(users)))

	w.family("citrus_user_traffic_bytes_total", "counter", "Bytes of a user of an inbound (cumulative; not affected by /traffic/users?reset).")
	for _, u := range users {
		w.int("citrus_user_traffic_bytes_total", u.Up, "inbound", u.Key.Inbound, "user", u.Key.User, "direction", "up")
		w.int("citrus_user_traffic_bytes_total", u.Down, "inbound", u.Key.Inbound, "user", u.Key.User, "direction", "down")
	}
	w.family("citrus_user_connections", "gauge", "Open connections and UDP sessions of a user.")
	for _, u := range users {
		w.int("citrus_user_connections", u.Conns, "inbound", u.Key.Inbound, "user", u.Key.User)
	}
	w.family("citrus_user_online_ips", "gauge", "Online source addresses of a user, as max-ips counts them.")
	for _, u := range users {
		w.int("citrus_user_online_ips", u.OnlineIPs, "inbound", u.Key.Inbound, "user", u.Key.User)
	}
	w.family("citrus_user_rejected_total", "counter", "Connections of a user refused by its limits, by reason.")
	for _, u := range users {
		if len(u.Rejected) == 0 {
			continue
		}
		reasons := make([]string, 0, len(u.Rejected))
		for reason := range u.Rejected {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		for _, reason := range reasons {
			w.int("citrus_user_rejected_total", u.Rejected[reason], "inbound", u.Key.Inbound, "user", u.Key.User, "reason", reason)
		}
	}
}

type proxyHealth struct {
	name  string
	alive bool
	delay uint16
}

// writeProxies reports the proxies (and groups) that a health check or a
// delay test has tested at least once; the others have no meaningful state.
func writeProxies(w writer) {
	seen := map[string]bool{}
	var list []proxyHealth
	add := func(p C.Proxy) {
		name := p.Name()
		if seen[name] {
			return
		}
		seen[name] = true
		history := p.DelayHistory()
		if len(history) == 0 {
			return
		}
		list = append(list, proxyHealth{name: name, alive: p.AliveForTestUrl(""), delay: history[len(history)-1].Delay})
	}
	for _, p := range tunnel.Proxies() {
		add(p)
	}
	for _, pd := range tunnel.Providers() {
		for _, p := range pd.Proxies() {
			add(p)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].name < list[j].name })

	w.family("citrus_proxy_alive", "gauge", "1 when the last health check of a proxy succeeded.")
	for _, p := range list {
		w.int("citrus_proxy_alive", boolValue(p.alive), "proxy", p.name)
	}
	w.family("citrus_proxy_delay_ms", "gauge", "Delay of the last successful health check of a proxy in milliseconds.")
	for _, p := range list {
		if p.alive && p.delay > 0 {
			w.int("citrus_proxy_delay_ms", int64(p.delay), "proxy", p.name)
		}
	}
}

// writeChains reports the chain groups that a health check has tested: the
// chain, and the hops whose state the check told (the hops up to the first one
// that failed; all of them when the chain is alive).
func writeChains(w writer) {
	type chainHealth struct {
		name   string
		status outboundgroup.ChainStatus
	}
	var list []chainHealth
	for name, p := range tunnel.Proxies() {
		if c, ok := p.Adapter().(*outboundgroup.Chain); ok {
			if st := c.Status(); st.Checked {
				list = append(list, chainHealth{name: name, status: st})
			}
		}
	}
	if len(list) == 0 {
		return
	}
	sort.Slice(list, func(i, j int) bool { return list[i].name < list[j].name })

	w.family("citrus_chain_alive", "gauge", "1 when the last health check of a chain group got through all its hops.")
	for _, c := range list {
		w.int("citrus_chain_alive", boolValue(c.status.Alive), "chain", c.name)
	}
	w.family("citrus_chain_hop_alive", "gauge", "State of a hop of a chain group after its last health check: 0 for the first hop that failed, 1 for the hops before it (or all hops of a chain that is alive); the hops after a failed one are not reported.")
	for _, c := range list {
		for _, h := range c.status.Hops {
			if h.Alive != nil {
				w.int("citrus_chain_hop_alive", boolValue(*h.Alive), "chain", c.name, "hop", h.Name, "position", strconv.Itoa(h.Position))
			}
		}
	}
}
