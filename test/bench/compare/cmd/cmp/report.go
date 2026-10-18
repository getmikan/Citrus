package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

type metric struct {
	key, title, unit string
	fmt              string
	get              func(*result) (float64, bool)
}

func bulkM(name string, f func(*bulkResult) float64) func(*result) (float64, bool) {
	return func(r *result) (float64, bool) {
		b, ok := r.Bulk[name]
		if !ok || b.Bytes == 0 {
			return 0, false
		}
		return f(b), true
	}
}

var metrics = []metric{
	{"dl1_mbps", "Download, 1 stream", "MB/s", "%.0f", bulkM("dl1", func(b *bulkResult) float64 { return b.MBps })},
	{"ul1_mbps", "Upload, 1 stream", "MB/s", "%.0f", bulkM("ul1", func(b *bulkResult) float64 { return b.MBps })},
	{"dl32_mbps", "Download, 32 streams", "MB/s", "%.0f", bulkM("dl32", func(b *bulkResult) float64 { return b.MBps })},
	{"ul32_mbps", "Upload, 32 streams", "MB/s", "%.0f", bulkM("ul32", func(b *bulkResult) float64 { return b.MBps })},
	{"dl1_cpu_gb", "Server CPU per GB, download 1 stream (unpaced)", "CPU s/GB", "%.2f", bulkM("dl1", func(b *bulkResult) float64 { return b.CPUPerGB })},
	{"dl32_cpu_gb", "Server CPU per GB, download 32 streams", "CPU s/GB", "%.2f", bulkM("dl32", func(b *bulkResult) float64 { return b.CPUPerGB })},
	{"ul32_cpu_gb", "Server CPU per GB, upload 32 streams", "CPU s/GB", "%.2f", bulkM("ul32", func(b *bulkResult) float64 { return b.CPUPerGB })},
	{"dlfix_cpu_gb", "Server CPU per GB at 500 Mbit/s, download", "CPU s/GB", "%.2f", bulkM("dl1_fixed", func(b *bulkResult) float64 { return b.CPUPerGB })},
	{"ulfix_cpu_gb", "Server CPU per GB at 500 Mbit/s, upload", "CPU s/GB", "%.2f", bulkM("ul1_fixed", func(b *bulkResult) float64 { return b.CPUPerGB })},
	{"dlfix_cores", "Server cores busy at 500 Mbit/s, download", "cores", "%.3f", bulkM("dl1_fixed", func(b *bulkResult) float64 { return b.ServerCores })},
	{"hs_rate", "New connections per second (128 concurrent clients)", "conn/s", "%.0f", func(r *result) (float64, bool) {
		if r.Handshake == nil || r.Handshake.Conns == 0 {
			return 0, false
		}
		return r.Handshake.Rate, true
	}},
	{"hs_ttfb_p50", "Time to first byte, p50 (handshake phase)", "ms", "%.1f", func(r *result) (float64, bool) {
		if r.Handshake == nil || r.Handshake.Conns == 0 {
			return 0, false
		}
		return r.Handshake.TTFBp50, true
	}},
	{"hs_ttfb_p99", "Time to first byte, p99 (handshake phase)", "ms", "%.1f", func(r *result) (float64, bool) {
		if r.Handshake == nil || r.Handshake.Conns == 0 {
			return 0, false
		}
		return r.Handshake.TTFBp99, true
	}},
	{"hs_cpu_ms", "Server CPU per new connection", "CPU ms", "%.3f", func(r *result) (float64, bool) {
		if r.Handshake == nil || r.Handshake.Conns == 0 {
			return 0, false
		}
		return r.Handshake.CPUmsPerConn, true
	}},
	{"mem1k_rss", "RSS per idle tunnel, 1000 tunnels", "KiB", "%.1f", memM(0, false)},
	{"mem5k_rss", "RSS per idle tunnel, 5000 tunnels", "KiB", "%.1f", memM(1, false)},
	{"mem_slope", "RSS per added idle tunnel between 1000 and 5000 (no baseline involved)", "KiB", "%.1f", func(r *result) (float64, bool) {
		if r.Memory == nil || len(r.Memory.Points) < 2 {
			return 0, false
		}
		a, b := r.Memory.Points[0], r.Memory.Points[1]
		if !full(a) || !full(b) {
			return 0, false
		}
		return (float64(b.RSS) - float64(a.RSS)) / float64(b.Reached-a.Reached) / 1024, true
	}},
	{"mem5k_cg", "cgroup memory (incl. kernel socket buffers) per idle tunnel, 5000 tunnels", "KiB", "%.1f", memM(1, true)},
	{"mem5k_total", "Server RSS with 5000 idle tunnels", "MiB", "%.1f", func(r *result) (float64, bool) {
		if r.Memory == nil || len(r.Memory.Points) < 2 {
			return 0, false
		}
		if !full(r.Memory.Points[1]) {
			return 0, false
		}
		return float64(r.Memory.Points[1].RSS) / (1 << 20), true
	}},
	{"lat_idle_p50", "Echo RTT on an idle server, p50", "ms", "%.2f", latM(func(l *latResult) float64 { return l.IdleRTTp50 })},
	{"lat_idle_p99", "Echo RTT on an idle server, p99", "ms", "%.2f", latM(func(l *latResult) float64 { return l.IdleRTTp99 })},
	{"lat_load_p50", "Echo RTT during an 8-stream bulk download, p50", "ms", "%.2f", latM(func(l *latResult) float64 { return l.LoadRTTp50 })},
	{"lat_load_p99", "Echo RTT during an 8-stream bulk download, p99", "ms", "%.2f", latM(func(l *latResult) float64 { return l.LoadRTTp99 })},
	{"lat_ttfb_p50", "New connection TTFB during the bulk download, p50", "ms", "%.2f", latM(func(l *latResult) float64 { return l.LoadTTFBp50 })},
	{"lat_ttfb_p99", "New connection TTFB during the bulk download, p99", "ms", "%.2f", latM(func(l *latResult) float64 { return l.LoadTTFBp99 })},
	{"lat_bulk_mbps", "Bulk download alongside the latency probe", "MB/s", "%.0f", latM(func(l *latResult) float64 { return l.LoadMBps })},
	{"client_util_max", "Highest client-container CPU use in any window (bottleneck check)", "%", "%.0f", func(r *result) (float64, bool) {
		m := 0.0
		for _, b := range r.Bulk {
			m = max(m, b.ClientUtil)
		}
		if r.Handshake != nil {
			m = max(m, r.Handshake.ClientUtil)
		}
		if r.Latency != nil {
			m = max(m, r.Latency.ClientUtil)
		}
		return m * 100, m > 0
	}},
}

var shortTitle = map[string]string{
	"dl1_mbps": "dl 1 stream", "ul1_mbps": "ul 1 stream", "dl32_mbps": "dl 32 streams", "ul32_mbps": "ul 32 streams",
	"dl32_cpu_gb": "dl 32 streams", "ul32_cpu_gb": "ul 32 streams", "dlfix_cpu_gb": "dl @500 Mbit/s", "ulfix_cpu_gb": "ul @500 Mbit/s",
	"hs_rate": "rate", "hs_ttfb_p50": "TTFB p50", "hs_ttfb_p99": "TTFB p99", "hs_cpu_ms": "server CPU per conn",
	"mem5k_rss": "RSS per tunnel @5000", "mem_slope": "RSS per added tunnel 1000→5000", "mem5k_cg": "cgroup memory per tunnel @5000", "mem5k_total": "RSS @5000",
	"lat_idle_p50": "echo RTT idle p50", "lat_load_p50": "echo RTT under load p50", "lat_load_p99": "echo RTT under load p99",
	"lat_ttfb_p50": "new conn TTFB under load p50", "lat_bulk_mbps": "bulk alongside",
}

func memM(i int, cg bool) func(*result) (float64, bool) {
	return func(r *result) (float64, bool) {
		if r.Memory == nil || len(r.Memory.Points) <= i {
			return 0, false
		}
		p := r.Memory.Points[i]
		if !full(p) {
			return 0, false
		}
		if cg {
			return p.MemPerConn / 1024, true
		}
		return p.RSSPerConn / 1024, true
	}
}

func latM(f func(*latResult) float64) func(*result) (float64, bool) {
	return func(r *result) (float64, bool) {
		if r.Latency == nil || r.Latency.Samples == 0 {
			return 0, false
		}
		return f(r.Latency), true
	}
}

var protoOrder = []string{"reality", "reality-x25519", "reality-tlsin", "xhttp", "trojan", "ss2022", "hy2", "tuic", "anytls"}

// higherBetter: +1 when a larger value is better, -1 when a smaller one is,
// 0 for the bookkeeping metrics (no winner).
func higherBetter(key string) int {
	switch {
	case key == "client_util_max":
		return 0
	case strings.HasSuffix(key, "_mbps"), key == "hs_rate":
		return 1
	}
	return -1
}

// headlineKeys are the metrics of headline.md (per-protocol winners).
var headlineKeys = []string{
	"dl32_mbps", "ul32_mbps", "dl1_mbps", "ul1_mbps",
	"dlfix_cpu_gb", "ulfix_cpu_gb", "dl32_cpu_gb", "ul32_cpu_gb",
	"hs_rate", "hs_cpu_ms", "hs_ttfb_p99",
	"mem1k_rss", "mem5k_rss", "mem5k_cg",
	"lat_load_p50", "lat_load_p99", "lat_ttfb_p50",
}

// stat is the median and range of one metric over the repetitions of one
// server × protocol.
type stat struct {
	n             int
	med, min, max float64
	vals          []float64
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	dir := fs.String("dir", "", "results directory (runs/*.json)")
	fs.Parse(args)
	files, err := filepath.Glob(filepath.Join(*dir, "runs", "*.json"))
	if err != nil {
		return err
	}
	type key struct{ proto, server string }
	runs := map[key][]*result{}
	var anomalies []string
	keyshares := map[key]map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var r result
		if err := json.Unmarshal(b, &r); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		k := key{r.Proto, r.Server}
		runs[k] = append(runs[k], &r)
		for _, a := range r.Anomalies {
			anomalies = append(anomalies, fmt.Sprintf("%s / %s / rep %d: %s", r.Proto, r.Server, r.Rep, a))
		}
		if r.KeyShare != "" {
			if keyshares[k] == nil {
				keyshares[k] = map[string]bool{}
			}
			keyshares[k][r.KeyShare] = true
		}
	}
	statOf := func(p, s string, m metric) (stat, bool) {
		var st stat
		for _, r := range runs[key{p, s}] {
			if v, ok := m.get(r); ok {
				st.vals = append(st.vals, v)
			}
		}
		if len(st.vals) == 0 {
			return st, false
		}
		sort.Float64s(st.vals)
		st.n, st.med, st.min, st.max = len(st.vals), median(st.vals), st.vals[0], st.vals[len(st.vals)-1]
		return st, true
	}
	// no data: "n/a" when the server has no such inbound, "–" otherwise
	missing := func(p, s string) string {
		if !supported(s, p) {
			return "n/a"
		}
		return "–"
	}
	header := "| protocol |"
	var titles []string
	for _, s := range servers {
		header += " " + serverTitle[s] + " |"
		titles = append(titles, serverTitle[s])
	}
	header += "\n|---|" + strings.Repeat("---|", len(servers)) + "\n"

	cf, err := os.Create(filepath.Join(*dir, "summary.csv"))
	if err != nil {
		return err
	}
	defer cf.Close()
	cw := csv.NewWriter(cf)
	cw.Write([]string{"metric", "unit", "proto", "server", "n", "median", "min", "max", "values"})

	var md strings.Builder
	md.WriteString("<!-- generated by `cmp report`; median (min–max) over the repetitions; n/a: the server has no such inbound -->\n\n")
	for _, m := range metrics {
		var rows []string
		for _, p := range protoOrder {
			var cells []string
			any := false
			for _, s := range servers {
				st, ok := statOf(p, s, m)
				if !ok {
					cells = append(cells, missing(p, s))
					continue
				}
				any = true
				var vs []string
				for _, v := range st.vals {
					vs = append(vs, fmt.Sprintf(m.fmt, v))
				}
				cw.Write([]string{m.key, m.unit, p, s, fmt.Sprint(st.n),
					fmt.Sprintf(m.fmt, st.med), fmt.Sprintf(m.fmt, st.min), fmt.Sprintf(m.fmt, st.max),
					strings.Join(vs, " ")})
				cells = append(cells, fmt.Sprintf(m.fmt+" ("+m.fmt+"–"+m.fmt+")", st.med, st.min, st.max))
			}
			if any {
				rows = append(rows, fmt.Sprintf("| %s | %s |\n", p, strings.Join(cells, " | ")))
			}
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&md, "#### %s, %s\n\n%s", m.title, m.unit, header)
		for _, r := range rows {
			md.WriteString(r)
		}
		md.WriteString("\n")
	}
	cw.Flush()

	md.WriteString("#### TLS key exchange the server picked (probe; not run for the QUIC protocols)\n\n" + header)
	for _, p := range protoOrder {
		var cells []string
		any := false
		for _, s := range servers {
			ks := keyshares[key{p, s}]
			if len(ks) == 0 {
				cells = append(cells, missing(p, s))
				continue
			}
			any = true
			var names []string
			for n := range ks {
				names = append(names, n)
			}
			slices.Sort(names)
			cells = append(cells, strings.Join(names, ", "))
		}
		if any {
			fmt.Fprintf(&md, "| %s | %s |\n", p, strings.Join(cells, " | "))
		}
	}
	// Vision direct copy per bulk phase (reality-tlsin), summed over the
	// repetitions: streams whose upload / download went direct, of all.
	var vrows []string
	for _, p := range protoOrder {
		for _, ph := range []string{"dl1", "ul1", "dl32", "ul32", "dl1_fixed", "ul1_fixed"} {
			var cells []string
			any := false
			for _, s := range servers {
				var n, up, down, noLog int
				for _, r := range runs[key{p, s}] {
					b, ok := r.Bulk[ph]
					if !ok {
						continue
					}
					if b.Vision == nil {
						noLog++
						continue
					}
					n += b.Streams
					up += b.Vision.UpDirect
					down += b.Vision.DownDirect
				}
				switch {
				case n == 0 && noLog == 0:
					cells = append(cells, missing(p, s))
				case n == 0:
					cells = append(cells, "no log")
					any = true
				default:
					c := fmt.Sprintf("up %d/%d, down %d/%d", up, n, down, n)
					if noLog > 0 {
						c += fmt.Sprintf(" (%d runs without log)", noLog)
					}
					cells = append(cells, c)
					any = true
				}
			}
			if any && p == "reality-tlsin" {
				vrows = append(vrows, fmt.Sprintf("| %s %s | %s |\n", p, ph, strings.Join(cells, " | ")))
			}
		}
	}
	if len(vrows) > 0 {
		md.WriteString("\n#### Vision direct copy: streams that switched, of all (Xray client's debug log, every repetition)\n\n" +
			strings.Replace(header, "| protocol |", "| protocol, phase |", 1))
		for _, r := range vrows {
			md.WriteString(r)
		}
	}
	md.WriteString("\n#### Anomalies recorded by the harness\n\n")
	if len(anomalies) == 0 {
		md.WriteString("None.\n")
	}
	slices.Sort(anomalies)
	for _, a := range anomalies {
		fmt.Fprintf(&md, "- %s\n", a)
	}
	if err := os.WriteFile(filepath.Join(*dir, "tables.md"), []byte(md.String()), 0o644); err != nil {
		return err
	}

	// compact.md: medians only, one cell per protocol with every server, a
	// few metrics per table (for RESULTS.md and the PR description).
	medianOf := func(p, s string, m metric) string {
		st, ok := statOf(p, s, m)
		if !ok {
			return missing(p, s)
		}
		return fmt.Sprintf(m.fmt, st.med)
	}
	byKey := map[string]metric{}
	for _, m := range metrics {
		byKey[m.key] = m
	}
	var cm strings.Builder
	fmt.Fprintf(&cm, "<!-- generated by `cmp report`; medians, %s -->\n", strings.Join(titles, " / "))
	for _, t := range []struct {
		title string
		keys  []string
	}{
		{"Throughput, MB/s", []string{"dl1_mbps", "ul1_mbps", "dl32_mbps", "ul32_mbps"}},
		{"Server CPU, CPU seconds per GB", []string{"dl32_cpu_gb", "ul32_cpu_gb", "dlfix_cpu_gb", "ulfix_cpu_gb"}},
		{"New connections", []string{"hs_rate", "hs_ttfb_p50", "hs_ttfb_p99", "hs_cpu_ms"}},
		{"Idle tunnels", []string{"mem5k_rss", "mem_slope", "mem5k_cg", "mem5k_total"}},
		{"Latency", []string{"lat_idle_p50", "lat_load_p50", "lat_load_p99", "lat_ttfb_p50", "lat_bulk_mbps"}},
	} {
		fmt.Fprintf(&cm, "\n#### %s\n\n| protocol |", t.title)
		for _, k := range t.keys {
			fmt.Fprintf(&cm, " %s, %s |", shortTitle[k], byKey[k].unit)
		}
		cm.WriteString("\n|---|" + strings.Repeat("---|", len(t.keys)) + "\n")
		for _, p := range protoOrder {
			row := "| " + p
			any := false
			for _, k := range t.keys {
				var cells []string
				for _, s := range servers {
					v := medianOf(p, s, byKey[k])
					any = any || (v != "–" && v != "n/a")
					cells = append(cells, v)
				}
				row += " | " + strings.Join(cells, " / ")
			}
			if any {
				cm.WriteString(row + " |\n")
			}
		}
	}
	if err := os.WriteFile(filepath.Join(*dir, "compact.md"), []byte(cm.String()), 0o644); err != nil {
		return err
	}

	// headline.md: per metric and protocol, the medians and ranges, the
	// winner, and whether the win is outside the noise: "≈" lists every
	// server whose min–max range overlaps the best one's. "Citrus vs best
	// other" is the difference of the medians, positive = Citrus better.
	var hl strings.Builder
	hl.WriteString("<!-- generated by `cmp report`; median (min–max); winner: best median, bold when no other " +
		"server's range overlaps it, otherwise \"≈\" with every overlapping server (a tie within the noise) -->\n")
	for _, k := range headlineKeys {
		m, ok := byKey[k]
		if !ok {
			continue
		}
		dirn := float64(higherBetter(k))
		bestOf := func(sts map[string]stat, skip string) string {
			best := ""
			for _, s := range servers {
				st, ok := sts[s]
				if !ok || s == skip {
					continue
				}
				if best == "" || dirn*(st.med-sts[best].med) > 0 {
					best = s
				}
			}
			return best
		}
		var rows []string
		for _, p := range protoOrder {
			sts := map[string]stat{}
			for _, s := range servers {
				if st, ok := statOf(p, s, m); ok {
					sts[s] = st
				}
			}
			if len(sts) == 0 {
				continue
			}
			best := bestOf(sts, "")
			var ties []string
			for _, s := range servers {
				st, ok := sts[s]
				if !ok || s == best {
					continue
				}
				if st.min <= sts[best].max && sts[best].min <= st.max {
					ties = append(ties, serverTitle[s])
				}
			}
			winner := "**" + serverTitle[best] + "**"
			switch {
			case len(sts) < 2:
				winner = "(one server)"
			case len(ties) > 0:
				winner = "≈ " + serverTitle[best] + ", " + strings.Join(ties, ", ")
			}
			vs := "–"
			if c, ok := sts["citrus"]; ok {
				if other := bestOf(sts, "citrus"); other != "" && sts[other].med != 0 {
					d := (c.med - sts[other].med) / sts[other].med * 100 * dirn
					vs = fmt.Sprintf("%+.0f%% vs %s", d, serverTitle[other])
				}
			}
			if notComparable[p][k] && !visionAllDirect(runs, p) {
				winner, vs = "not comparable (client-side Vision switch)", "–"
			}
			row := "| " + p
			for _, s := range servers {
				st, ok := sts[s]
				if !ok {
					row += " | " + missing(p, s)
					continue
				}
				row += " | " + fmt.Sprintf(m.fmt+" ("+m.fmt+"–"+m.fmt+")", st.med, st.min, st.max)
			}
			rows = append(rows, row+" | "+winner+" | "+vs+" |\n")
		}
		if len(rows) == 0 {
			continue
		}
		better := "lower is better"
		if dirn > 0 {
			better = "higher is better"
		}
		fmt.Fprintf(&hl, "\n#### %s, %s (%s)\n\n| protocol |", m.title, m.unit, better)
		for _, s := range servers {
			hl.WriteString(" " + serverTitle[s] + " |")
		}
		hl.WriteString(" winner | Citrus vs best other |\n|---|" + strings.Repeat("---|", len(servers)+2) + "\n")
		for _, r := range rows {
			hl.WriteString(r)
		}
	}
	if err := os.WriteFile(filepath.Join(*dir, "headline.md"), []byte(hl.String()), 0o644); err != nil {
		return err
	}
	fmt.Printf("%d runs -> %s\n", len(files), filepath.Join(*dir, "tables.md"))
	return nil
}

func median(v []float64) float64 {
	n := len(v)
	if n%2 == 1 {
		return v[n/2]
	}
	return (v[n/2-1] + v[n/2]) / 2
}

// full: the level was reached. A server that refuses tunnels past a limit
// (Citrus TUIC: 2048 streams per QUIC connection) has no value at that level,
// rather than one computed over fewer tunnels; the anomaly says why.
func full(p memPoint) bool { return p.Reached == p.Target }

// notComparable lists metrics whose value a protocol variant's client decides
// rather than the server. reality-tlsin uploads: Xray's client switches Vision
// to direct copy only when one of its reads holds nothing but whole TLS
// records. Before the TLS sink's ready byte and upload ack (handleSinkTLS)
// that depended on how the inner command record and the bulk data split
// across its socket reads, so a stream was padded to the end (~400 MB/s on
// any server) or went direct (~3000 MB/s) at random. The metrics are ranked
// only when the client log shows every upload stream of every run going
// direct (visionAllDirect): never for results recorded before the fix, which
// have no Vision data.
var notComparable = map[string]map[string]bool{
	"reality-tlsin": {"ul1_mbps": true, "ul32_mbps": true, "ul32_cpu_gb": true, "ulfix_cpu_gb": true},
}

// visionAllDirect: every upload phase of every run of the protocol has
// Vision data, and all its streams went direct.
func visionAllDirect[K comparable](runs map[K][]*result, proto string) bool {
	seen := false
	for _, rs := range runs {
		for _, r := range rs {
			if r.Proto != proto {
				continue
			}
			for _, b := range r.Bulk {
				if b.Dir != "up" {
					continue
				}
				if b.Vision == nil || b.Vision.Streams != b.Streams || b.Vision.UpDirect != b.Streams {
					return false
				}
				seen = true
			}
		}
	}
	return seen
}
