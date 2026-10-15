package main

import (
	"fmt"
	"strings"
)

func kb(b float64) string { return fmt.Sprintf("%.1f", b/1024) }

func markdown(r *report) string {
	var b strings.Builder
	m := r.Meta
	fmt.Fprintf(&b, "# Citrus load benchmark: %s, %s\n\n", m.Date, m.Host)
	fmt.Fprintf(&b, "- Host: %s/%s, %d CPUs, %s\n", m.OS, m.Arch, m.CPUs, m.GoVersion)
	fmt.Fprintf(&b, "- Citrus: %s", m.CitrusVer)
	if m.Commit != "" {
		fmt.Fprintf(&b, " (commit %s)", m.Commit)
	}
	fmt.Fprintf(&b, "\n- Server GOMAXPROCS: %d; inbound on %s; duration budget per scenario: %s; idle steps: %v; connection-rate workers: %d\n",
		m.ServerProcs, m.ServerHost, m.Duration, m.IdleLevels, m.RateWorkers)
	fmt.Fprintf(&b, "- Command: `bench %s`; total %.0f s\n", strings.Join(m.Args, " "), m.TotalSecond)
	b.WriteString("- Everything on loopback: server = Citrus inbound -> DIRECT -> local sink; client = Citrus outbound in the driver process. ")
	b.WriteString("Memory, goroutines and CPU are the server process only. KB = 1024 bytes, MB/s = 10^6 bytes/s.\n\n")

	all := append(append([]scenarioResult{}, r.Scenarios...), r.Variants...)

	b.WriteString("## Idle connections (per connection, after GC, minus the baseline)\n\n")
	b.WriteString("| Scenario | Variant | Conns | RSS KB/conn | Heap KB/conn | Stack KB/conn | Goroutines/conn | Server RSS MB | Open s | Errors | Goroutines left after close |\n")
	b.WriteString("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, s := range all {
		if s.Idle == nil {
			continue
		}
		for _, p := range s.Idle.Points {
			reached := fmt.Sprint(p.Reached)
			if p.Reached < p.Target {
				reached = fmt.Sprintf("%d of %d", p.Reached, p.Target)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %.2f | %.1f | %.1f | %d | %d (base %d) |\n",
				s.Scenario, s.Variant, reached, kb(p.RSSPerConn), kb(p.HeapPerConn), kb(p.StackPerConn),
				p.GoroutinesPer, mb(p.RSS), p.OpenSeconds, p.Errors, s.Idle.GoroutinesClosed, s.Idle.Base.Goroutines)
		}
	}

	b.WriteString("\n## Throughput (server CPU per 10^9 bytes relayed)\n\n")
	b.WriteString("| Scenario | Variant | Phase | MB/s | Gbit/s | Server CPU s/GB | Server cores | Server RSS MB | Errors |\n")
	b.WriteString("|---|---|---|---:|---:|---:|---:|---:|---:|\n")
	for _, s := range all {
		for _, t := range s.Throughput {
			fmt.Fprintf(&b, "| %s | %s | %s | %.0f | %.2f | %.2f | %.2f | %.1f | %d |\n",
				s.Scenario, s.Variant, t.Name, t.MBps, t.Gbps, t.CPUPerGB, t.Cores, mb(t.RSS), t.Errors)
		}
	}

	if m.RateWorkers == 0 {
		b.WriteString("\nConnection-rate phase off (`-rate`).\n")
	} else {
		b.WriteString("\n## Connection rate (new connection, short request, sink answers and closes)\n\n")
		b.WriteString("| Scenario | Variant | Conn/s | p50 ms | p99 ms | Server CPU ms/conn | Server cores | Errors |\n")
		b.WriteString("|---|---|---:|---:|---:|---:|---:|---:|\n")
		for _, s := range all {
			if s.Rate == nil {
				continue
			}
			t := s.Rate
			fmt.Fprintf(&b, "| %s | %s | %.0f | %.2f | %.2f | %.3f | %.2f | %d |\n",
				s.Scenario, s.Variant, t.PerSec, t.P50ms, t.P99ms, t.CPUmsPer, t.Cores, t.Errors)
		}
	}

	var notes []string
	for _, s := range all {
		if s.Error != "" {
			notes = append(notes, fmt.Sprintf("- %s [%s]: error: %s", s.Scenario, s.Variant, s.Error))
		}
		if s.Idle != nil {
			for _, p := range s.Idle.Points {
				if p.FirstError != "" {
					notes = append(notes, fmt.Sprintf("- %s [%s] idle %d: first error: %s", s.Scenario, s.Variant, p.Target, p.FirstError))
				}
			}
		}
		for _, t := range s.Throughput {
			if t.FirstError != "" {
				notes = append(notes, fmt.Sprintf("- %s [%s] %s: first error: %s", s.Scenario, s.Variant, t.Name, t.FirstError))
			}
		}
		if s.Rate != nil && s.Rate.FirstError != "" {
			notes = append(notes, fmt.Sprintf("- %s [%s] rate: first error: %s", s.Scenario, s.Variant, s.Rate.FirstError))
		}
	}
	seen := map[string]bool{}
	var sn []string
	for _, s := range r.Scenarios {
		if s.Note != "" && !seen[s.Scenario] {
			seen[s.Scenario] = true
			sn = append(sn, fmt.Sprintf("- %s: %s", s.Scenario, s.Note))
		}
	}
	if len(sn) > 0 {
		b.WriteString("\n## Scenario notes\n\n")
		b.WriteString(strings.Join(sn, "\n") + "\n")
	}
	if len(notes) > 0 {
		b.WriteString("\n## Errors\n\n")
		b.WriteString(strings.Join(notes, "\n") + "\n")
	}
	return b.String()
}
