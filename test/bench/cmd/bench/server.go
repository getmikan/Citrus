package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"runtime/metrics"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
)

// serverStats is what the server process reports about itself on /stats.
type serverStats struct {
	Goroutines int     `json:"goroutines"`
	HeapLive   uint64  `json:"heap_live"`    // live heap after the last GC
	HeapObj    uint64  `json:"heap_obj"`     // heap memory occupied by objects (live + not yet swept)
	Stacks     uint64  `json:"stacks"`       // goroutine stacks
	GoMapped   uint64  `json:"go_mapped"`    // all memory mapped by the Go runtime minus what it released
	RSS        uint64  `json:"rss"`          // resident set (Linux) / working set (Windows); 0 if unknown
	CPUUser    float64 `json:"cpu_user"`     // process user CPU seconds
	CPUSys     float64 `json:"cpu_sys"`      // process system CPU seconds
	GCCycles   uint64  `json:"gc_cycles"`    // completed GC cycles
	GOMAXPROCS int     `json:"gomaxprocs"`   // of the server process
	HasProcCPU bool    `json:"has_proc_cpu"` // CPUUser/CPUSys come from the OS
}

func (s serverStats) CPU() float64 { return s.CPUUser + s.CPUSys }

var metricNames = []string{
	"/sched/goroutines:goroutines",
	"/gc/heap/live:bytes",
	"/memory/classes/heap/objects:bytes",
	"/memory/classes/heap/stacks:bytes",
	"/memory/classes/total:bytes",
	"/memory/classes/heap/released:bytes",
	"/gc/cycles/total:gc-cycles",
}

func readStats(gc bool) serverStats {
	if gc {
		// Twice: the first GC moves sync.Pool contents to the victim cache,
		// the second frees them, so pooled buffers do not count as live.
		runtime.GC()
		runtime.GC()
	}
	samples := make([]metrics.Sample, len(metricNames))
	for i, n := range metricNames {
		samples[i].Name = n
	}
	metrics.Read(samples)
	u := func(i int) uint64 {
		if samples[i].Value.Kind() == metrics.KindUint64 {
			return samples[i].Value.Uint64()
		}
		return 0
	}
	s := serverStats{
		Goroutines: int(u(0)),
		HeapLive:   u(1),
		HeapObj:    u(2),
		Stacks:     u(3),
		GoMapped:   u(4) - u(5),
		GCCycles:   u(6),
		GOMAXPROCS: runtime.GOMAXPROCS(0),
	}
	if s.Goroutines == 0 {
		s.Goroutines = runtime.NumGoroutine()
	}
	s.RSS = processRSS()
	s.CPUUser, s.CPUSys, s.HasProcCPU = processCPU()
	return s
}

// runServer is the server role: the Citrus core (hub.Parse, the same entry as
// the citrus binary) plus a small HTTP endpoint with /stats and /debug/pprof.
// It exits when its standard input is closed, so it never outlives the driver.
func runServer(configPath, home, statsAddr string) {
	C.SetHomeDir(home)
	cfg, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read config:", err)
		os.Exit(1)
	}
	if err := hub.Parse(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "parse config:", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(readStats(r.URL.Query().Get("gc") == "1"))
	})
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	ln, err := net.Listen("tcp", statsAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stats listen:", err)
		os.Exit(1)
	}
	go http.Serve(ln, mux)
	fmt.Println("ready")

	io.Copy(io.Discard, os.Stdin)
	executor.Shutdown()
	os.Exit(0)
}
