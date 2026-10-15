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
		if b.Reached <= a.Reached {
			return 0, false
		}
		return (float64(b.RSS) - float64(a.RSS)) / float64(b.Reached-a.Reached) / 1024, true
	}},
	{"mem5k_cg", "cgroup memory (incl. kernel socket buffers) per idle tunnel, 5000 tunnels", "KiB", "%.1f", memM(1, true)},
	{"mem5k_total", "Server RSS with 5000 idle tunnels", "MiB", "%.1f", func(r *result) (float64, bool) {
		if r.Memory == nil || len(r.Memory.Points) < 2 {
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

var protoOrder = []string{"reality", "reality-x25519", "reality-tlsin", "xhttp", "trojan", "ss2022"}

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

	cf, err := os.Create(filepath.Join(*dir, "summary.csv"))
	if err != nil {
		return err
	}
	defer cf.Close()
	cw := csv.NewWriter(cf)
	cw.Write([]string{"metric", "unit", "proto", "server", "n", "median", "min", "max", "values"})

	var md strings.Builder
	md.WriteString("<!-- generated by `cmp report`; median (min–max) over the repetitions -->\n\n")
	for _, m := range metrics {
		type row struct {
			proto string
			cells []string
		}
		var rows []row
		for _, p := range protoOrder {
			var cells []string
			any := false
			for _, s := range servers {
				var vals []float64
				for _, r := range runs[key{p, s}] {
					if v, ok := m.get(r); ok {
						vals = append(vals, v)
					}
				}
				if len(vals) == 0 {
					cells = append(cells, "–")
					continue
				}
				any = true
				sort.Float64s(vals)
				med := median(vals)
				var vs []string
				for _, v := range vals {
					vs = append(vs, fmt.Sprintf(m.fmt, v))
				}
				cw.Write([]string{m.key, m.unit, p, s, fmt.Sprint(len(vals)),
					fmt.Sprintf(m.fmt, med), fmt.Sprintf(m.fmt, vals[0]), fmt.Sprintf(m.fmt, vals[len(vals)-1]),
					strings.Join(vs, " ")})
				cells = append(cells, fmt.Sprintf(m.fmt+" ("+m.fmt+"–"+m.fmt+")", med, vals[0], vals[len(vals)-1]))
			}
			if any {
				rows = append(rows, row{p, cells})
			}
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&md, "#### %s, %s\n\n| protocol | Xray | mihomo | Citrus |\n|---|---|---|---|\n", m.title, m.unit)
		for _, r := range rows {
			fmt.Fprintf(&md, "| %s | %s |\n", r.proto, strings.Join(r.cells, " | "))
		}
		md.WriteString("\n")
	}
	cw.Flush()

	md.WriteString("#### TLS key exchange the server picked (probe)\n\n| protocol | Xray | mihomo | Citrus |\n|---|---|---|---|\n")
	for _, p := range protoOrder {
		var cells []string
		any := false
		for _, s := range servers {
			ks := keyshares[key{p, s}]
			if len(ks) == 0 {
				cells = append(cells, "–")
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

	// compact.md: medians only, "Xray / mihomo / Citrus" per cell, a few
	// metrics per table (for RESULTS.md and the PR description).
	medianOf := func(p, s string, m metric) string {
		var vals []float64
		for _, r := range runs[key{p, s}] {
			if v, ok := m.get(r); ok {
				vals = append(vals, v)
			}
		}
		if len(vals) == 0 {
			return "–"
		}
		sort.Float64s(vals)
		return fmt.Sprintf(m.fmt, median(vals))
	}
	byKey := map[string]metric{}
	for _, m := range metrics {
		byKey[m.key] = m
	}
	var cm strings.Builder
	cm.WriteString("<!-- generated by `cmp report`; medians, Xray / mihomo / Citrus -->\n")
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
					any = any || v != "–"
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
