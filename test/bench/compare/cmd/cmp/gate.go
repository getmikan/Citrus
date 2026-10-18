package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// The CI perf check (.github/workflows/perf-nightly.yml): Citrus and mihomo
// run in the same job on a shared runner, whose absolute numbers drift from
// run to run. What is compared against the committed baseline is the ratio
// of the two, oriented so that above 1 means Citrus is better (Citrus/mihomo
// for throughput and rates, mihomo/Citrus for CPU and memory). A metric
// fails when its ratio falls more than the tolerance below the baseline's.

// gateKeys are the metrics the gate compares (see metrics in report.go).
var gateKeys = []string{
	"dl32_mbps", "ul32_mbps", "dl1_mbps", "ul1_mbps",
	"dl32_cpu_gb", "ul32_cpu_gb",
	"hs_rate", "hs_cpu_ms",
	"mem1k_rss",
}

type baseline struct {
	Note      string                        `json:"note,omitempty"`
	Tolerance float64                       `json:"tolerance"`
	Ratios    map[string]map[string]float64 `json:"ratios"` // proto -> metric -> ratio
}

func cmdGate(args []string) error {
	fs := flag.NewFlagSet("gate", flag.ExitOnError)
	dir := fs.String("dir", "", "results directory (runs/*.json)")
	base := fs.String("baseline", "", "baseline ratios (JSON) to compare against")
	write := fs.String("write", "", "write this run's ratios as a new baseline to this file")
	summary := fs.String("summary", "", "append the markdown table to this file (e.g. $GITHUB_STEP_SUMMARY)")
	tol := fs.Float64("tolerance", 0, "allowed drop of a ratio below the baseline's (0: the baseline's own, else 0.2)")
	fs.Parse(args)

	files, err := filepath.Glob(filepath.Join(*dir, "runs", "*.json"))
	if err != nil {
		return err
	}
	runs := map[[2]string][]*result{} // proto, server
	var protos []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var r result
		if err := json.Unmarshal(b, &r); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		runs[[2]string{r.Proto, r.Server}] = append(runs[[2]string{r.Proto, r.Server}], &r)
		if !slices.Contains(protos, r.Proto) {
			protos = append(protos, r.Proto)
		}
	}
	slices.SortFunc(protos, func(a, b string) int { return slices.Index(protoOrder, a) - slices.Index(protoOrder, b) })
	byKey := map[string]metric{}
	for _, m := range metrics {
		byKey[m.key] = m
	}
	med := func(p, s string, m metric) (float64, int, bool) {
		var v []float64
		for _, r := range runs[[2]string{p, s}] {
			if x, ok := m.get(r); ok && x > 0 {
				v = append(v, x)
			}
		}
		if len(v) == 0 {
			return 0, 0, false
		}
		sort.Float64s(v)
		return median(v), len(v), true
	}

	var bl baseline
	if *base != "" {
		b, err := os.ReadFile(*base)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &bl); err != nil {
			return fmt.Errorf("%s: %w", *base, err)
		}
	}
	if *tol == 0 {
		*tol = bl.Tolerance
	}
	if *tol == 0 {
		*tol = 0.2
	}

	cur := baseline{Tolerance: *tol, Ratios: map[string]map[string]float64{},
		Note: "Citrus/mihomo ratios (above 1 = Citrus better), medians of a CI run on " + time.Now().UTC().Format("2006-01-02")}
	var md strings.Builder
	fmt.Fprintf(&md, "### Citrus vs mihomo, ratio against the baseline (fails below %.0f%% of it)\n\n", (1-*tol)*100)
	md.WriteString("Ratio: Citrus/mihomo for MB/s and conn/s, mihomo/Citrus for CPU and memory; above 1 = Citrus better.\n\n")
	md.WriteString("| protocol | metric | Citrus | mihomo | ratio | baseline | vs baseline | |\n|---|---|---|---|---|---|---|---|\n")
	var failed []string
	for _, p := range protos {
		for _, k := range gateKeys {
			m := byKey[k]
			want, hasBase := bl.Ratios[p][k]
			c, nc, okc := med(p, "citrus", m)
			h, nh, okh := med(p, "mihomo", m)
			if !okc && !okh {
				continue
			}
			row := func(ratio, vs, status string) {
				cs, hs := "–", "–"
				if okc {
					cs = fmt.Sprintf(m.fmt+" (n=%d)", c, nc)
				}
				if okh {
					hs = fmt.Sprintf(m.fmt+" (n=%d)", h, nh)
				}
				bs := "–"
				if hasBase {
					bs = fmt.Sprintf("%.3f", want)
				}
				fmt.Fprintf(&md, "| %s | %s, %s | %s | %s | %s | %s | %s | %s |\n", p, m.title, m.unit, cs, hs, ratio, bs, vs, status)
			}
			switch {
			case !okc:
				// Citrus produced no number where mihomo did: its run failed
				row("–", "–", "FAIL (no Citrus value)")
				failed = append(failed, p+" "+k+": no Citrus value")
				continue
			case !okh:
				row("–", "–", "skipped (no mihomo value)")
				continue
			}
			ratio := c / h
			if higherBetter(k) < 0 {
				ratio = h / c
			}
			if cur.Ratios[p] == nil {
				cur.Ratios[p] = map[string]float64{}
			}
			cur.Ratios[p][k] = round3(ratio)
			if !hasBase {
				row(fmt.Sprintf("%.3f", ratio), "–", "no baseline")
				continue
			}
			d := ratio/want - 1
			status := "ok"
			if d < -*tol {
				status = "**FAIL**"
				failed = append(failed, fmt.Sprintf("%s %s: ratio %.3f, baseline %.3f (%+.0f%%)", p, k, ratio, want, d*100))
			}
			row(fmt.Sprintf("%.3f", ratio), fmt.Sprintf("%+.0f%%", d*100), status)
		}
	}
	md.WriteString("\n")
	if len(failed) > 0 {
		md.WriteString("**Regressions:**\n\n")
		for _, f := range failed {
			md.WriteString("- " + f + "\n")
		}
		md.WriteString("\n")
	}
	fmt.Print(md.String())
	if *summary != "" {
		f, err := os.OpenFile(*summary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		f.WriteString(md.String())
		f.Close()
	}
	if *write != "" {
		if err := writeJSON(*write, cur); err != nil {
			return err
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d metric(s) regressed against the baseline", len(failed))
	}
	return nil
}

func round3(v float64) float64 { return float64(int64(v*1000+0.5)) / 1000 }
