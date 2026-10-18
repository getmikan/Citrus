package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type measureOpts struct {
	server, proto string
	rep           int
	cfgDir        string
	out           string
	logDir        string
	xray, singbox string // client binaries
	serverCG      cgroup
	clientCG      cgroup
	sinkCG        cgroup
	dur           time.Duration // timed window of a throughput / handshake phase
	ramp          time.Duration // before each window, not measured
	idleLevels    []int
	settle        time.Duration // memory phase: wait before each reading
	hsWorkers     int
	fixedRate     int64 // bytes/s for the fixed-rate CPU phase
	phases        map[string]bool
	pprof         string // mihomo/Citrus external controller (log-level debug at start) to profile, or ""
	pprofDir      string
	pprofSecret   string
}

// --- results -------------------------------------------------------------------

type usage struct {
	ServerCPUSec float64 `json:"server_cpu_sec"`
	ServerCores  float64 `json:"server_cores"` // average cores the server kept busy
	ClientUtil   float64 `json:"client_util"`  // client container CPU / its cpuset
	SinkUtil     float64 `json:"sink_util"`    // sink container CPU / its cpuset
	WindowSec    float64 `json:"window_sec"`
}

type bulkResult struct {
	Streams    int     `json:"streams"`
	Dir        string  `json:"dir"`
	TargetMBps float64 `json:"target_mbps,omitempty"`
	MBps       float64 `json:"mbps"` // 10^6 bytes per second
	Bytes      int64   `json:"bytes"`
	CPUPerGB   float64 `json:"cpu_sec_per_gb"` // server CPU seconds per 10^9 bytes
	usage
	Errors     int    `json:"errors"`
	FirstError string `json:"first_error,omitempty"`
	// reality-tlsin: Vision on the Xray client, from its debug log. Streams
	// is the number of tunnels of the phase seen in the log, UpDirect those
	// whose upload switched to direct copy, DownDirect those whose download
	// did (the server's padding command).
	Vision *visionCount `json:"vision,omitempty"`
}

type hsResult struct {
	Workers        int     `json:"workers"`
	Conns          int     `json:"conns"`
	Rate           float64 `json:"conns_per_sec"`
	RateFirstHalf  float64 `json:"rate_first_half"`
	RateSecondHalf float64 `json:"rate_second_half"`
	TTFBp50        float64 `json:"ttfb_p50_ms"`
	TTFBp99        float64 `json:"ttfb_p99_ms"`
	CPUmsPerConn   float64 `json:"server_cpu_ms_per_conn"`
	usage
	Errors     int    `json:"errors"`
	FirstError string `json:"first_error,omitempty"`
}

type memPoint struct {
	Target     int     `json:"target"`
	Reached    int     `json:"reached"`
	OpenSec    float64 `json:"open_sec"`
	RSS        uint64  `json:"rss"`
	MemCurrent uint64  `json:"cgroup_memory_current"` // includes kernel socket buffers
	Anon       uint64  `json:"cgroup_anon"`
	Sock       uint64  `json:"cgroup_sock"`
	RSSPerConn float64 `json:"rss_per_conn"`
	MemPerConn float64 `json:"cgroup_mem_per_conn"`
	Errors     int     `json:"errors"`
	FirstError string  `json:"first_error,omitempty"`
}

type memResult struct {
	BaseRSS        uint64     `json:"base_rss"`
	BaseMemCurrent uint64     `json:"base_cgroup_memory_current"`
	Points         []memPoint `json:"points"`
	AfterCloseRSS  uint64     `json:"after_close_rss"`
}

type latResult struct {
	IdleRTTp50  float64 `json:"idle_rtt_p50_ms"`
	IdleRTTp99  float64 `json:"idle_rtt_p99_ms"`
	LoadRTTp50  float64 `json:"load_rtt_p50_ms"`
	LoadRTTp99  float64 `json:"load_rtt_p99_ms"`
	LoadTTFBp50 float64 `json:"load_new_conn_ttfb_p50_ms"`
	LoadTTFBp99 float64 `json:"load_new_conn_ttfb_p99_ms"`
	LoadMBps    float64 `json:"load_bulk_mbps"`
	BulkStreams int     `json:"bulk_streams"`
	Samples     int     `json:"rtt_samples"`
	usage
	Errors     int    `json:"errors"`
	FirstError string `json:"first_error,omitempty"`
}

type result struct {
	Server     string                 `json:"server"`
	Proto      string                 `json:"proto"`
	Rep        int                    `json:"rep"`
	Start      time.Time              `json:"start"`
	KeyShare   string                 `json:"keyshare,omitempty"`
	Memory     *memResult             `json:"memory,omitempty"`
	Handshake  *hsResult              `json:"handshake,omitempty"`
	Bulk       map[string]*bulkResult `json:"bulk,omitempty"`
	Latency    *latResult             `json:"latency,omitempty"`
	RSSStart   uint64                 `json:"rss_start"`
	RSSEnd     uint64                 `json:"rss_end"`
	ServerCPUs int                    `json:"server_cpus"`
	ClientCPUs int                    `json:"client_cpus"`
	Anomalies  []string               `json:"anomalies,omitempty"`
	Seconds    float64                `json:"seconds"`
}

// --- command ---------------------------------------------------------------------

func cmdMeasure(args []string) error {
	fs := flag.NewFlagSet("measure", flag.ExitOnError)
	o := measureOpts{}
	fs.StringVar(&o.server, "server", "", "xray|singbox|mihomo|citrus (label only)")
	fs.StringVar(&o.proto, "proto", "", "reality|reality-x25519|reality-tlsin|xhttp|trojan|ss2022|hy2|tuic|anytls")
	fs.IntVar(&o.rep, "rep", 1, "repetition number (label only)")
	fs.StringVar(&o.cfgDir, "cfg", "/cfg", "config directory (material.json)")
	fs.StringVar(&o.out, "out", "", "result JSON path")
	fs.StringVar(&o.logDir, "logs", "/tmp", "where the client logs go")
	fs.StringVar(&o.xray, "xray", "/opt/bin/xray", "Xray binary (client of the protocols Xray speaks)")
	fs.StringVar(&o.singbox, "singbox", "/opt/bin/sing-box", "sing-box binary (client of TUIC and AnyTLS)")
	scg := fs.String("server-cg", "", "server container cgroup directory")
	ccg := fs.String("client-cg", "", "client container cgroup directory")
	kcg := fs.String("sink-cg", "", "sink container cgroup directory")
	fs.DurationVar(&o.dur, "dur", 10*time.Second, "measured window per phase")
	fs.DurationVar(&o.ramp, "ramp", 2*time.Second, "unmeasured ramp before each window")
	idle := fs.String("idle", "1000,5000", "idle tunnel levels")
	fs.DurationVar(&o.settle, "settle", 5*time.Second, "memory phase: wait before each reading")
	fs.IntVar(&o.hsWorkers, "hs-workers", 128, "concurrent clients in the handshake phase")
	fs.StringVar(&o.pprof, "pprof", "", "external controller URL of a mihomo/Citrus server started with log-level debug: "+
		"the log level is set to warning, then a CPU profile is taken in every handshake and bulk window")
	fs.StringVar(&o.pprofDir, "pprof-dir", "/results/pprof", "where the profiles go")
	fs.StringVar(&o.pprofSecret, "pprof-secret", "", "secret of the external controller")
	rate := fs.Float64("rate-mbit", 500, "fixed rate for the CPU efficiency phase, Mbit/s")
	fs.StringVar(&fpDefault, "fp", fpDefault, "client uTLS fingerprint of the REALITY runs other than reality-x25519")
	phases := fs.String("phases", "", "comma list: mem,hs,bulk,fixed,lat (default by proto)")
	fs.Parse(args)

	if o.out == "" || o.server == "" || o.proto == "" {
		return fmt.Errorf("-out, -server and -proto are required")
	}
	o.serverCG, o.clientCG, o.sinkCG = cgroup{*scg}, cgroup{*ccg}, cgroup{*kcg}
	o.fixedRate = int64(*rate * 1e6 / 8)
	for _, s := range strings.Split(*idle, ",") {
		var n int
		fmt.Sscan(s, &n)
		if n > 0 {
			o.idleLevels = append(o.idleLevels, n)
		}
	}
	if *phases == "" {
		switch o.proto {
		case "reality-x25519":
			*phases = "hs" // the data path is that of reality; only the key exchange differs
		case "reality-tlsin":
			*phases = "bulk,fixed" // only Vision's inner-TLS data path differs
		default:
			*phases = "mem,hs,bulk,fixed,lat"
		}
	}
	o.phases = map[string]bool{}
	for _, p := range strings.Split(*phases, ",") {
		o.phases[p] = true
	}
	res, err := measure(o)
	if res != nil {
		if werr := writeJSON(o.out, res); werr != nil && err == nil {
			err = werr
		}
	}
	return err
}

type runner struct {
	o   measureOpts
	d   *dialer
	res *result
}

func (r *runner) anomaly(f string, a ...any) {
	s := fmt.Sprintf(f, a...)
	fmt.Fprintln(os.Stderr, "  ANOMALY:", s)
	r.res.Anomalies = append(r.res.Anomalies, s)
}

func measure(o measureOpts) (*result, error) {
	t0 := time.Now()
	res := &result{Server: o.server, Proto: o.proto, Rep: o.rep, Start: t0,
		ServerCPUs: o.serverCG.ncpu(), ClientCPUs: o.clientCG.ncpu()}
	if res.ClientCPUs == 0 {
		res.ClientCPUs = runtime.NumCPU()
	}
	var m material
	b, err := os.ReadFile(filepath.Join(o.cfgDir, "material.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	serverAddr := fmt.Sprintf("%s:%d", serverIP, serverPort)
	readyTimeout := 30 * time.Second
	if isQUIC(o.proto) {
		// UDP: nothing to dial; the end to end check below waits instead
		readyTimeout = 60 * time.Second
	} else if err := waitTCP(serverAddr, 60*time.Second); err != nil {
		return nil, err
	}

	// Which TLS key exchange the server picks for this client (TLS protocols).
	if baseProto(o.proto) != "ss2022" && !isQUIC(o.proto) {
		res.KeyShare = probeKeyShare(o, &m, serverAddr)
		fmt.Fprintf(os.Stderr, "  keyshare: %s\n", res.KeyShare)
	}

	const socksPort = 1080
	stop, err := startClient(o, "client", clientConfig(&m, o.proto, serverIP, serverPort, socksPort), socksPort)
	if err != nil {
		return nil, err
	}
	defer stop()
	var roots *x509.CertPool
	if o.proto == "reality-tlsin" {
		roots = x509.NewCertPool()
		roots.AppendCertsFromPEM([]byte(m.CertPEM))
	}
	r := &runner{o: o, d: newDialer(socksPort, roots), res: res}

	// End to end check: mihomo and Citrus open the listener before the tunnel
	// runs, and drop connections in between.
	if err := r.ready(readyTimeout); err != nil {
		return res, err
	}
	if o.pprof != "" {
		// debug enables /debug/pprof at start; the logging itself is turned down again
		req, _ := http.NewRequest(http.MethodPatch, o.pprof+"/configs", strings.NewReader(`{"log-level":"warning"}`))
		req.Header.Set("Authorization", "Bearer "+o.pprofSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return res, fmt.Errorf("pprof: %w", err)
		}
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return res, fmt.Errorf("pprof: PATCH /configs: %s", resp.Status)
		}
	}
	r.warmup()
	res.RSSStart = o.serverCG.rss()

	if o.phases["mem"] {
		fmt.Fprintln(os.Stderr, "  memory")
		res.Memory = r.memory()
	}
	if o.phases["hs"] {
		fmt.Fprintln(os.Stderr, "  handshake")
		res.Handshake = r.handshake()
	}
	res.Bulk = map[string]*bulkResult{}
	if o.phases["bulk"] {
		for _, c := range []struct {
			name    string
			streams int
			dir     byte
		}{{"dl1", 1, cmdDownload}, {"ul1", 1, cmdUpload}, {"dl32", 32, cmdDownload}, {"ul32", 32, cmdUpload}} {
			fmt.Fprintln(os.Stderr, "  bulk", c.name)
			res.Bulk[c.name] = r.bulk(c.streams, c.dir, 0)
		}
	}
	if o.phases["fixed"] {
		fmt.Fprintln(os.Stderr, "  fixed rate")
		res.Bulk["dl1_fixed"] = r.bulk(1, cmdDownload, o.fixedRate)
		res.Bulk["ul1_fixed"] = r.bulk(1, cmdUpload, o.fixedRate)
	}
	if o.phases["lat"] {
		fmt.Fprintln(os.Stderr, "  latency")
		res.Latency = r.latency()
	}
	res.RSSEnd = o.serverCG.rss()
	if len(o.serverCG.pids()) == 0 && o.serverCG.dir != "" {
		r.anomaly("server process gone at the end of the run")
	}
	res.Seconds = time.Since(t0).Seconds()
	r.checkBottlenecks()
	return res, nil
}

// probeKeyShare runs a second client against a relay in front of the
// server and reads the key share group of the ServerHello.
func probeKeyShare(o measureOpts, m *material, serverAddr string) string {
	relay, ch, err := keyShareRelay(serverAddr)
	if err != nil {
		return "probe: " + err.Error()
	}
	host, port, _ := net.SplitHostPort(relay)
	var p int
	fmt.Sscan(port, &p)
	const probePort = 1081
	stop, err := startClient(o, "probe", clientConfig(m, o.proto, host, p, probePort), probePort)
	if err != nil {
		return "probe: " + err.Error()
	}
	defer stop()
	d := newDialer(probePort, nil)
	if c, err := d.open(cmdRequest, nil); err == nil {
		c.SetDeadline(time.Now().Add(10 * time.Second))
		io.ReadFull(c, make([]byte, replySize))
		c.Close()
	}
	select {
	case s := <-ch:
		return s
	case <-time.After(10 * time.Second):
		return "probe: timeout"
	}
}

// startClient starts the protocol's client (clientFor) with cfg, a SOCKS5
// inbound on socksPort.
func startClient(o measureOpts, role string, cfg obj, socksPort int) (func(), error) {
	// Per network (CMP_NET), so that two benchmark setups on a host do not
	// share the directory (and its pid file).
	dir := filepath.Join(os.TempDir(), "cmp-"+netPrefix()+"-"+role)
	path := filepath.Join(dir, "config.json")
	if err := writeJSON(path, cfg); err != nil {
		return nil, err
	}
	client := clientFor(o.proto)
	logf, err := os.Create(clientLog(o, role))
	if err != nil {
		return nil, err
	}
	// A client left over from an interrupted run would hold the port: kill
	// the one of the pid file. Not pkill: with --pid=host it reads every
	// process of the host, and blocks on one stuck in the kernel (D state).
	pidFile := filepath.Join(dir, "pid")
	killStale(pidFile, path)
	bin := o.xray
	if client == "singbox" {
		bin = o.singbox
	}
	cmd := exec.Command(bin, "run", "-c", path)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		logf.Close()
		return nil, err
	}
	os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o644)
	stop := func() {
		cmd.Process.Kill()
		cmd.Wait()
		logf.Close()
	}
	if err := waitTCP(fmt.Sprintf("127.0.0.1:%d", socksPort), 15*time.Second); err != nil {
		stop()
		return nil, err
	}
	return stop, nil
}

// killStale kills the process of pidFile if its command line still names
// cfgPath (the pid may have been reused).
func killStale(pidFile, cfgPath string) {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return
	}
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || !strings.Contains(string(cmdline), cfgPath) {
		return
	}
	if p, err := os.FindProcess(pid); err == nil {
		p.Kill()
		time.Sleep(200 * time.Millisecond)
	}
}

func clientLog(o measureOpts, role string) string {
	return filepath.Join(o.logDir, fmt.Sprintf("%s-%s-%s-rep%d.log", o.server, o.proto, clientFor(o.proto)+"-"+role, o.rep))
}

func (r *runner) ready(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if _, err := r.request(); err == nil {
			return nil
		} else {
			last = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("no traffic through the server after %s: %v", timeout, last)
}

// request opens a tunnel, sends a request, reads the 64-byte answer, and
// returns the time to its first byte.
func (r *runner) request() (time.Duration, error) {
	t0 := time.Now()
	c, err := r.d.open(cmdRequest, nil)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(dialTimeout))
	var buf [replySize]byte
	if _, err := io.ReadFull(c, buf[:1]); err != nil {
		return 0, err
	}
	ttfb := time.Since(t0)
	if _, err := io.ReadFull(c, buf[1:]); err != nil {
		return 0, err
	}
	return ttfb, nil
}

// warmup: bulk transfer on a few streams and a few hundred connections, so
// that pools, buffers and the Go runtime of the server are past their start.
func (r *runner) warmup() {
	saved := r.o.dur
	r.o.dur = 3 * time.Second
	r.bulk(8, cmdDownload, 0)
	r.o.dur = saved
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				r.request()
			}
		}()
	}
	wg.Wait()
	time.Sleep(2 * time.Second)
}

type snap struct {
	t                  time.Time
	srv, client, sinkC time.Duration
}

func (r *runner) snap() snap {
	return snap{time.Now(), r.o.serverCG.cpu(), r.o.clientCG.cpu(), r.o.sinkCG.cpu()}
}

func (r *runner) usage(a, b snap) usage {
	w := b.t.Sub(a.t).Seconds()
	u := usage{WindowSec: w, ServerCPUSec: (b.srv - a.srv).Seconds()}
	u.ServerCores = u.ServerCPUSec / w
	if n := r.res.ClientCPUs; n > 0 {
		u.ClientUtil = (b.client - a.client).Seconds() / w / float64(n)
	}
	if n := r.o.sinkCG.ncpu(); n > 0 {
		u.SinkUtil = (b.sinkC - a.sinkC).Seconds() / w / float64(n)
	}
	return u
}

// profile starts a CPU profile and a heap-allocation (delta) profile of the
// server over the window (-pprof) and returns a func that waits for them to
// be saved.
func (r *runner) profile(name string) func() {
	if r.o.pprof == "" {
		return func() {}
	}
	var wg sync.WaitGroup
	for _, kind := range []string{"cpu", "allocs"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			path := "profile"
			if kind != "cpu" {
				path = kind
			}
			url := fmt.Sprintf("%s/debug/pprof/%s?seconds=%d", r.o.pprof, path, int(r.o.dur.Seconds()))
			req, _ := http.NewRequest(http.MethodGet, url, nil)
			req.Header.Set("Authorization", "Bearer "+r.o.pprofSecret)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				r.anomaly("pprof %s %s: %v", name, kind, err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				r.anomaly("pprof %s %s: %s", name, kind, resp.Status)
				return
			}
			os.MkdirAll(r.o.pprofDir, 0o755)
			f, err := os.Create(filepath.Join(r.o.pprofDir, fmt.Sprintf("%s-%s-%s-%s.pb.gz", r.o.server, r.o.proto, name, kind)))
			if err != nil {
				r.anomaly("pprof %s %s: %v", name, kind, err)
				return
			}
			io.Copy(f, resp.Body)
			f.Close()
		}()
	}
	return wg.Wait
}

// --- bulk transfer -------------------------------------------------------------------

type errBox struct {
	mu    sync.Mutex
	n     int
	first string
}

func (e *errBox) add(err error) {
	e.mu.Lock()
	e.n++
	if e.first == "" {
		e.first = err.Error()
	}
	e.mu.Unlock()
}

// bulk runs streams tunnels in one direction; rate > 0 paces each stream at
// rate bytes/s (the sink paces downloads, this process uploads).
func (r *runner) bulk(streams int, dir byte, rate int64) *bulkResult {
	res := &bulkResult{Streams: streams, Dir: map[byte]string{cmdDownload: "down", cmdUpload: "up"}[dir]}
	if rate > 0 {
		res.TargetMBps = float64(rate*int64(streams)) / 1e6
	}
	var logFrom int64 = -1
	if r.o.proto == "reality-tlsin" {
		logFrom = fileSize(clientLog(r.o, "client"))
	}
	var counter atomic.Int64
	var stopping atomic.Bool
	var errs errBox
	stopCh := make(chan struct{})
	conns := make([]net.Conn, 0, streams)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		var c net.Conn
		var err error
		switch {
		case dir == cmdDownload && rate > 0:
			c, err = r.d.open(cmdPaced, u64(rate))
		default:
			c, err = r.d.open(dir, nil)
		}
		if err != nil {
			errs.add(err)
			continue
		}
		mu.Lock()
		conns = append(conns, c)
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if dir == cmdDownload {
				_, err = io.CopyBuffer(countWriter{io.Discard, &counter}, c, make([]byte, 64*1024))
			} else if rate > 0 {
				pacedWrite(countWriter{c, &counter}, rate, stopCh)
			} else {
				cw := countWriter{c, &counter}
				for err == nil {
					_, err = cw.Write(junk)
				}
			}
			if !stopping.Load() {
				if err == nil {
					err = io.ErrUnexpectedEOF
				}
				errs.add(err)
			}
		}()
	}
	time.Sleep(r.o.ramp)
	a, ab := r.snap(), counter.Load()
	profDone := r.profile(fmt.Sprintf("%s%d%s", res.Dir, streams, map[bool]string{true: "-fixed"}[rate > 0]))
	time.Sleep(r.o.dur)
	b, bb := r.snap(), counter.Load()
	profDone()
	stopping.Store(true)
	close(stopCh)
	for _, c := range conns {
		c.Close()
	}
	wg.Wait()

	res.usage = r.usage(a, b)
	res.Bytes = bb - ab
	res.MBps = float64(res.Bytes) / 1e6 / res.WindowSec
	if res.Bytes > 0 {
		res.CPUPerGB = res.ServerCPUSec / (float64(res.Bytes) / 1e9)
	}
	res.Errors, res.FirstError = errs.n, errs.first
	if res.Errors > 0 {
		r.anomaly("bulk %d x %s: %d errors, first: %s", streams, res.Dir, res.Errors, res.FirstError)
	}
	if rate > 0 && res.MBps < 0.95*res.TargetMBps {
		r.anomaly("fixed rate %s: %.1f MB/s of %.1f", res.Dir, res.MBps, res.TargetMBps)
	}
	time.Sleep(time.Second) // let the closes propagate before the next phase
	if logFrom >= 0 {
		v, err := visionFromLog(clientLog(r.o, "client"), logFrom)
		if err != nil {
			r.anomaly("vision %d x %s: %v", streams, res.Dir, err)
		} else {
			res.Vision = v
			if v.Streams != streams || v.UpDirect != streams || v.DownDirect != streams {
				r.anomaly("vision %d x %s: %d streams in the client log, upload direct on %d, download direct on %d",
					streams, res.Dir, v.Streams, v.UpDirect, v.DownDirect)
			}
		}
	}
	return res
}

// --- handshake rate ------------------------------------------------------------------

func (r *runner) handshake() *hsResult {
	res := &hsResult{Workers: r.o.hsWorkers}
	var stop atomic.Bool
	start := time.Now()
	wStart := start.Add(r.o.ramp)
	wEnd := wStart.Add(r.o.dur)
	mid := wStart.Add(r.o.dur / 2)
	var errs errBox
	type wres struct {
		ttfb        []time.Duration
		first, last int
	}
	out := make([]wres, r.o.hsWorkers)
	var wg sync.WaitGroup
	for w := 0; w < r.o.hsWorkers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for !stop.Load() {
				t0 := time.Now()
				ttfb, err := r.request()
				end := time.Now()
				if t0.Before(wStart) || end.After(wEnd) {
					continue
				}
				if err != nil {
					errs.add(err)
					continue
				}
				out[w].ttfb = append(out[w].ttfb, ttfb)
				if end.Before(mid) {
					out[w].first++
				} else {
					out[w].last++
				}
			}
		}(w)
	}
	time.Sleep(time.Until(wStart))
	a := r.snap()
	profDone := r.profile("handshake")
	time.Sleep(time.Until(wEnd))
	b := r.snap()
	profDone()
	stop.Store(true)
	wg.Wait()

	var all []time.Duration
	var first, last int
	for _, o := range out {
		all = append(all, o.ttfb...)
		first += o.first
		last += o.last
	}
	res.usage = r.usage(a, b)
	res.Conns = len(all)
	res.Rate = float64(res.Conns) / res.WindowSec
	res.RateFirstHalf = float64(first) / (r.o.dur.Seconds() / 2)
	res.RateSecondHalf = float64(last) / (r.o.dur.Seconds() / 2)
	res.TTFBp50, res.TTFBp99 = pct(all, 0.50), pct(all, 0.99)
	if res.Conns > 0 {
		res.CPUmsPerConn = res.ServerCPUSec * 1000 / float64(res.Conns)
	}
	res.Errors, res.FirstError = errs.n, errs.first
	if res.Errors > 0 {
		r.anomaly("handshake: %d errors, first: %s", res.Errors, res.FirstError)
	}
	if res.RateFirstHalf > 0 && res.RateSecondHalf < 0.85*res.RateFirstHalf {
		r.anomaly("handshake rate fell from %.0f/s to %.0f/s within the window", res.RateFirstHalf, res.RateSecondHalf)
	}
	time.Sleep(2 * time.Second)
	return res
}

func pct(v []time.Duration, q float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := slices.Clone(v)
	slices.Sort(s)
	i := int(math.Ceil(q*float64(len(s)))) - 1
	if i < 0 {
		i = 0
	}
	return float64(s[i]) / 1e6
}

// --- idle tunnels ----------------------------------------------------------------------

func (r *runner) openIdle() (net.Conn, error) {
	c, err := r.d.open(cmdEcho, nil)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(dialTimeout))
	msg := []byte("idle-tunnel")
	if _, err := c.Write(msg); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := io.ReadFull(c, make([]byte, len(msg))); err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

func (r *runner) memory() *memResult {
	settle := r.o.settle
	time.Sleep(settle)
	g := r.o.serverCG
	res := &memResult{BaseRSS: g.rss(), BaseMemCurrent: g.memCurrent()}
	var conns []net.Conn
	var mu sync.Mutex
	for _, level := range r.o.idleLevels {
		p := memPoint{Target: level}
		var errs errBox
		t0 := time.Now()
		need := level - len(conns)
		var next atomic.Int64
		var wg sync.WaitGroup
		for w := 0; w < 64; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for next.Add(1) <= int64(need) {
					c, err := r.openIdle()
					if err != nil {
						errs.add(err)
						continue
					}
					mu.Lock()
					conns = append(conns, c)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		p.OpenSec = time.Since(t0).Seconds()
		time.Sleep(settle)
		p.Reached = len(conns)
		p.RSS, p.MemCurrent = g.rss(), g.memCurrent()
		p.Anon, p.Sock = g.memStat("anon"), g.memStat("sock")
		if p.Reached > 0 {
			p.RSSPerConn = (float64(p.RSS) - float64(res.BaseRSS)) / float64(p.Reached)
			p.MemPerConn = (float64(p.MemCurrent) - float64(res.BaseMemCurrent)) / float64(p.Reached)
		}
		p.Errors, p.FirstError = errs.n, errs.first
		if p.Errors > 0 {
			r.anomaly("idle %d: %d errors, first: %s", level, p.Errors, p.FirstError)
		}
		res.Points = append(res.Points, p)
	}
	// The tunnels must still work after idling.
	broken := 0
	for i, c := range conns {
		if i%50 != 0 {
			continue
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("x")); err != nil {
			broken++
			continue
		}
		if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
			broken++
		}
	}
	if broken > 0 {
		r.anomaly("idle tunnels: %d of %d checked no longer echo", broken, (len(conns)+49)/50)
	}
	for _, c := range conns {
		c.Close()
	}
	time.Sleep(settle)
	res.AfterCloseRSS = g.rss()
	return res
}

// --- latency under load --------------------------------------------------------------

func (r *runner) rtts(c net.Conn, n int, every time.Duration) ([]time.Duration, error) {
	msg := make([]byte, 64)
	buf := make([]byte, 64)
	var out []time.Duration
	tick := time.NewTicker(every)
	defer tick.Stop()
	for i := 0; i < n; i++ {
		<-tick.C
		c.SetDeadline(time.Now().Add(10 * time.Second))
		t0 := time.Now()
		if _, err := c.Write(msg); err != nil {
			return out, err
		}
		if _, err := io.ReadFull(c, buf); err != nil {
			return out, err
		}
		out = append(out, time.Since(t0))
	}
	return out, nil
}

func (r *runner) latency() *latResult {
	const every = 20 * time.Millisecond
	const bulkStreams = 8
	res := &latResult{BulkStreams: bulkStreams}
	var errs errBox
	ping, err := r.openIdle()
	if err != nil {
		r.anomaly("latency: %v", err)
		return res
	}
	defer ping.Close()
	idle, err := r.rtts(ping, 250, every)
	if err != nil {
		errs.add(err)
	}
	res.IdleRTTp50, res.IdleRTTp99 = pct(idle, 0.5), pct(idle, 0.99)

	// Bulk download on 8 streams, unpaced, for the whole window.
	var counter atomic.Int64
	var stopping atomic.Bool
	var conns []net.Conn
	var wg sync.WaitGroup
	for i := 0; i < bulkStreams; i++ {
		c, err := r.d.open(cmdDownload, nil)
		if err != nil {
			errs.add(err)
			continue
		}
		conns = append(conns, c)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := io.CopyBuffer(countWriter{io.Discard, &counter}, c, make([]byte, 64*1024))
			if !stopping.Load() {
				errs.add(fmt.Errorf("bulk stream ended: %v", err))
			}
		}()
	}
	time.Sleep(r.o.ramp)
	a, ab := r.snap(), counter.Load()
	n := int(r.o.dur / every)

	// New connections at 10/s alongside, time to first byte.
	var ttfb []time.Duration
	var tmu sync.Mutex
	stopNew := make(chan struct{})
	var nwg sync.WaitGroup
	nwg.Add(1)
	go func() {
		defer nwg.Done()
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stopNew:
				return
			case <-t.C:
				nwg.Add(1)
				go func() {
					defer nwg.Done()
					d, err := r.request()
					if err != nil {
						errs.add(err)
						return
					}
					tmu.Lock()
					ttfb = append(ttfb, d)
					tmu.Unlock()
				}()
			}
		}
	}()
	loaded, err := r.rtts(ping, n, every)
	if err != nil {
		errs.add(err)
	}
	b, bb := r.snap(), counter.Load()
	close(stopNew)
	nwg.Wait()
	stopping.Store(true)
	for _, c := range conns {
		c.Close()
	}
	wg.Wait()

	res.usage = r.usage(a, b)
	res.LoadMBps = float64(bb-ab) / 1e6 / res.WindowSec
	res.LoadRTTp50, res.LoadRTTp99 = pct(loaded, 0.5), pct(loaded, 0.99)
	res.LoadTTFBp50, res.LoadTTFBp99 = pct(ttfb, 0.5), pct(ttfb, 0.99)
	res.Samples = len(loaded)
	res.Errors, res.FirstError = errs.n, errs.first
	if res.Errors > 0 {
		r.anomaly("latency: %d errors, first: %s", res.Errors, res.FirstError)
	}
	return res
}

// checkBottlenecks flags windows where the client or the sink was busy enough
// to be the limit instead of the server.
func (r *runner) checkBottlenecks() {
	check := func(name string, u usage) {
		if u.ClientUtil > 0.7 {
			r.anomaly("%s: client container at %.0f%% of its CPUs", name, u.ClientUtil*100)
		}
		if u.SinkUtil > 0.7 {
			r.anomaly("%s: sink container at %.0f%% of its CPUs", name, u.SinkUtil*100)
		}
	}
	for k, b := range r.res.Bulk {
		check("bulk "+k, b.usage)
	}
	if h := r.res.Handshake; h != nil {
		check("handshake", h.usage)
	}
	if l := r.res.Latency; l != nil {
		check("latency", l.usage)
	}
}
