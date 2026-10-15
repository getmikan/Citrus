// Command bench is a load and benchmark harness for the Citrus server.
//
// The server is the Citrus core (hub.Parse, as in the citrus binary) running
// in a child process: this same executable started with -role server. The
// driver process runs the clients (Citrus outbounds, in-process) and a local
// sink that every proxied connection goes to through DIRECT. Server memory,
// goroutines and CPU are read from inside the server process, so the client
// side does not pollute them. See README.md.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

func logf(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
}

type scenarioResult struct {
	Scenario   string       `json:"scenario"`
	Variant    string       `json:"variant"`
	Note       string       `json:"note,omitempty"`
	Idle       *idleResult  `json:"idle,omitempty"`
	Throughput []throughput `json:"throughput,omitempty"`
	Rate       *connRate    `json:"rate,omitempty"`
	Error      string       `json:"error,omitempty"`
	Seconds    float64      `json:"seconds"`
}

type meta struct {
	Date        string   `json:"date"`
	Host        string   `json:"host"`
	OS          string   `json:"os"`
	Arch        string   `json:"arch"`
	CPUs        int      `json:"cpus"`
	GoVersion   string   `json:"go_version"`
	Commit      string   `json:"commit,omitempty"`
	CitrusVer   string   `json:"citrus_version"`
	ServerProcs int      `json:"server_gomaxprocs"`
	ServerHost  string   `json:"server_host"`
	Duration    string   `json:"duration"`
	IdleLevels  []int    `json:"idle_levels"`
	RateWorkers int      `json:"rate_workers"`
	Args        []string `json:"args"`
	TotalSecond float64  `json:"total_seconds"`
}

type report struct {
	Meta      meta             `json:"meta"`
	Scenarios []scenarioResult `json:"scenarios"`
	Variants  []scenarioResult `json:"variants"`
}

func main() {
	var (
		role      = flag.String("role", "driver", "driver, or server (internal: started by the driver)")
		cfgPath   = flag.String("config", "", "server role: configuration file")
		home      = flag.String("home", "", "server role: home directory")
		statsAddr = flag.String("stats", "", "server role: address of /stats and /debug/pprof")

		scenarioFlag = flag.String("scenario", "all", "comma-separated scenarios, or all: "+scenarioNames())
		duration     = flag.Duration("duration", 20*time.Second, "timed budget per scenario, split between the throughput and connection-rate phases")
		idleFlag     = flag.String("idle", "", "idle connection steps (default 1000,5000,10000; 1000,5000 on Windows)")
		variantsFlag = flag.String("variants", "vless-reality-vision,trojan-tls", "scenarios to repeat with user-stats off/on/on+limit, or none")
		procs        = flag.Int("server-procs", 4, "GOMAXPROCS of the server process (0: all CPUs)")
		workers      = flag.Int("workers", 64, "concurrent clients in the connection-rate phase")
		rateFlag     = flag.String("rate", "auto", "connection-rate phase: on, off, or auto (off on Windows, where it exhausts the ephemeral ports for minutes)")
		outDir       = flag.String("out", "results", "directory for the <date>-<host>.md/.json results")
		name         = flag.String("name", "", "results file name without extension (default <date>-<host>)")
		pprofDir     = flag.String("pprof", "", "save server CPU/heap/alloc profiles and goroutine dumps here (adds profiling overhead)")
		keep         = flag.Bool("keep", false, "keep the work directory (server configs and logs)")
	)
	flag.Parse()

	if *role == "server" {
		runServer(*cfgPath, *home, *statsAddr)
		return
	}
	log.SetLevel(log.ERROR)

	levels, err := parseLevels(*idleFlag)
	if err != nil {
		fatal(err)
	}
	var selected []*scenario
	if *scenarioFlag == "all" {
		for i := range scenarios {
			selected = append(selected, &scenarios[i])
		}
	} else {
		for _, n := range strings.Split(*scenarioFlag, ",") {
			s := findScenario(strings.TrimSpace(n))
			if s == nil {
				fatal(fmt.Errorf("unknown scenario %q (have %s)", n, scenarioNames()))
			}
			selected = append(selected, s)
		}
	}
	var variantScenarios []*scenario
	if *variantsFlag != "none" && *variantsFlag != "" {
		for _, n := range strings.Split(*variantsFlag, ",") {
			s := findScenario(strings.TrimSpace(n))
			if s == nil {
				fatal(fmt.Errorf("unknown variant scenario %q", n))
			}
			variantScenarios = append(variantScenarios, s)
		}
	}

	host, _ := os.Hostname()
	if h := os.Getenv("BENCH_HOST"); h != "" {
		host = h
	}
	start := time.Now()
	rep := report{Meta: meta{
		Date: start.Format("2006-01-02"), Host: host, OS: runtime.GOOS, Arch: runtime.GOARCH,
		CPUs: runtime.NumCPU(), GoVersion: runtime.Version(), Commit: gitCommit(), CitrusVer: C.Version,
		ServerProcs: *procs, Duration: duration.String(), IdleLevels: levels, RateWorkers: *workers,
		Args: os.Args[1:],
	}}

	work, err := os.MkdirTemp("", "citrus-bench-")
	if err != nil {
		fatal(err)
	}
	if *keep {
		logf("work directory: %s", work)
	} else {
		defer os.RemoveAll(work)
	}
	disableLoopbackDetector = pickServerHost()
	resolver.DisableIPv6 = false // the client dials ::1
	mat, err := newMaterial()
	if err != nil {
		fatal(err)
	}
	sink, err := startSink()
	if err != nil {
		fatal(err)
	}
	defer sink.Close()
	dest, err := startRealityDest(mat.cert)
	if err != nil {
		fatal(err)
	}
	defer dest.Close()
	env := benchEnv{mat: mat, sink: sink.Addr().(*net.TCPAddr).AddrPort(), dest: dest.Addr().String(),
		work: work, procs: *procs, workers: *workers, pprof: *pprofDir}
	switch *rateFlag {
	case "on":
	case "off":
		env.workers = 0
	case "auto":
		if runtime.GOOS == "windows" {
			env.workers = 0
		}
	default:
		fatal(fmt.Errorf("bad -rate %q", *rateFlag))
	}
	rep.Meta.RateWorkers = env.workers

	rep.Meta.ServerHost = serverHost
	logf("citrus bench: %s/%s, %d CPUs, server GOMAXPROCS=%d, %s, duration %s, idle %v, server on %s",
		runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), *procs, runtime.Version(), *duration, levels, serverHost)

	// Timed budget: down-1 25%, down-16 25%, up-16 20%, connection rate 30%.
	for _, s := range selected {
		r := env.run(s, variants[1], levels, []phase{
			{cmdDownload, 1, *duration * 25 / 100},
			{cmdDownload, 16, *duration * 25 / 100},
			{cmdUpload, 16, *duration * 20 / 100},
		}, *duration*30/100)
		rep.Scenarios = append(rep.Scenarios, r)
	}
	// Variants: idle at the first step, down-16 and connection rate, half each.
	for _, s := range variantScenarios {
		for _, v := range variants {
			r := env.run(s, v, levels[:1], []phase{{cmdDownload, 16, *duration / 2}}, *duration/2)
			rep.Variants = append(rep.Variants, r)
		}
	}
	rep.Meta.TotalSecond = time.Since(start).Seconds()

	if *name == "" {
		*name = rep.Meta.Date + "-" + sanitize(host)
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(err)
	}
	js, _ := json.MarshalIndent(rep, "", "  ")
	jsonPath := filepath.Join(*outDir, *name+".json")
	mdPath := filepath.Join(*outDir, *name+".md")
	if err := os.WriteFile(jsonPath, append(js, '\n'), 0o644); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(mdPath, []byte(markdown(&rep)), 0o644); err != nil {
		fatal(err)
	}
	logf("done in %s: %s, %s", time.Since(start).Round(time.Second), mdPath, jsonPath)
}

type phase struct {
	dir     byte
	streams int
	d       time.Duration
}

type benchEnv struct {
	mat     *material
	sink    netip.AddrPort
	dest    string
	work    string
	procs   int
	workers int
	pprof   string
}

func (e *benchEnv) run(s *scenario, v variant, levels []int, phases []phase, rateD time.Duration) (r scenarioResult) {
	r = scenarioResult{Scenario: s.name, Variant: v.name, Note: s.note}
	start := time.Now()
	defer func() { r.Seconds = time.Since(start).Seconds() }()
	logf("== %s [%s]", s.name, v.name)
	port, err := freePort(s.udp)
	if err != nil {
		r.Error = err.Error()
		return
	}
	dir := filepath.Join(e.work, s.name+"-"+v.name)
	p, err := startServer(dir, serverConfig(s, e.mat, port, e.dest, v), e.procs)
	if err != nil {
		r.Error = err.Error()
		logf("    error: %v", err)
		return
	}
	defer p.stop()
	var prof *profiler
	if e.pprof != "" {
		prof = &profiler{dir: e.pprof, prefix: sanitize(s.name + "-" + v.name)}
	}
	fail := func(phase string, err error) {
		msg := phase + ": " + err.Error()
		if r.Error == "" {
			r.Error = msg
		} else {
			r.Error += "; " + msg
		}
		logf("    error: %s", msg)
	}

	c := newClient(s, e.mat, port, e.sink)
	idle, err := runIdle(p, c, levels, prof)
	r.Idle = idle
	if err != nil {
		fail("idle", err)
	}
	c.close()

	// Fresh client for the timed phases: no leftovers of the idle phase.
	c = newClient(s, e.mat, port, e.sink)
	defer c.close()
	for _, ph := range phases {
		t, err := runThroughput(p, c, ph.dir, ph.streams, ph.d, prof, fmt.Sprintf("%c%d", ph.dir+'a'-'A', ph.streams))
		if err != nil {
			fail(t.Name, err)
			continue
		}
		r.Throughput = append(r.Throughput, t)
	}
	if e.workers == 0 {
		return
	}
	rate, err := runRate(p, c, e.workers, rateD, prof, "rate")
	if err != nil {
		fail("rate", err)
	} else {
		r.Rate = &rate
	}
	return
}

func parseLevels(s string) ([]int, error) {
	if s == "" {
		if runtime.GOOS == "windows" {
			// 16384 ephemeral ports by default, and every idle connection
			// takes two (client -> server, server -> sink).
			return []int{1000, 5000}, nil
		}
		return []int{1000, 5000, 10000}, nil
	}
	var out []int
	for _, f := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("bad -idle step %q", f)
		}
		if len(out) > 0 && n <= out[len(out)-1] {
			return nil, fmt.Errorf("-idle steps must increase")
		}
		out = append(out, n)
	}
	return out, nil
}

func gitCommit() string {
	if c := os.Getenv("BENCH_COMMIT"); c != "" {
		return c
	}
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		case r == '+':
			return '_'
		}
		return '-'
	}, s)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "bench:", err)
	os.Exit(1)
}
