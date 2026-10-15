package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const dialTimeout = 15 * time.Second

// --- idle connections --------------------------------------------------------------

type idlePoint struct {
	Target         int     `json:"target"`
	Reached        int     `json:"reached"`
	OpenSeconds    float64 `json:"open_seconds"` // time to open the connections of this step
	RSS            uint64  `json:"rss"`
	Goroutines     int     `json:"goroutines"`
	RSSPerConn     float64 `json:"rss_per_conn"`
	HeapPerConn    float64 `json:"heap_per_conn"`  // live heap
	StackPerConn   float64 `json:"stack_per_conn"` // goroutine stacks
	GoMappedPerCon float64 `json:"go_mapped_per_conn"`
	GoroutinesPer  float64 `json:"goroutines_per_conn"`
	Errors         int     `json:"errors"`
	FirstError     string  `json:"first_error,omitempty"`
}

type idleResult struct {
	Base             serverStats `json:"base"`
	Points           []idlePoint `json:"points"`
	GoroutinesClosed int         `json:"goroutines_after_close"` // leak check
	HeapClosed       uint64      `json:"heap_after_close"`
}

// openIdle opens one connection that has made a round trip through the server
// (so it is authenticated and has its upstream), then stays open.
func openIdle(c *client, i int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	conn, err := c.dial(ctx, i)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(dialTimeout))
	msg := []byte{cmdEcho, 'p', 'i', 'n', 'g', '-', 'b', 'e', 'n', 'c', 'h'}
	if _, err := conn.Write(msg); err != nil {
		conn.Close()
		return nil, err
	}
	buf := make([]byte, len(msg)-1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func runIdle(p *serverProc, c *client, levels []int, prof *profiler) (*idleResult, error) {
	// Warm up: pools, caches and lazily started goroutines are not per-connection costs.
	for i := 0; i < 8; i++ {
		conn, err := openIdle(c, i)
		if err != nil {
			return nil, fmt.Errorf("warm-up: %w", err)
		}
		conn.Close()
	}
	time.Sleep(time.Second)
	baseStats, err := p.stats(true)
	if err != nil {
		return nil, err
	}
	res := &idleResult{Base: baseStats}

	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	const workers = 64
	next := 0
	for li, target := range levels {
		start := time.Now()
		var errCount atomic.Int64
		var firstErr atomic.Value
		var wg sync.WaitGroup
		jobs := make(chan int)
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					conn, err := openIdle(c, i)
					if err != nil {
						if errCount.Add(1) == 1 {
							firstErr.Store(err.Error())
						}
						continue
					}
					mu.Lock()
					conns = append(conns, conn)
					mu.Unlock()
				}
			}()
		}
		for ; next < target; next++ {
			// Give up on a step that fails wholesale (e.g. out of ephemeral ports).
			if e := errCount.Load(); e > 200 && e > int64(next/10) {
				break
			}
			jobs <- next
		}
		close(jobs)
		wg.Wait()
		open := time.Since(start)
		time.Sleep(2 * time.Second)
		s, err := p.stats(true)
		if err != nil {
			return res, err
		}
		n := len(conns)
		pt := idlePoint{
			Target: target, Reached: n, OpenSeconds: open.Seconds(),
			RSS: s.RSS, Goroutines: s.Goroutines, Errors: int(errCount.Load()),
		}
		if fe, ok := firstErr.Load().(string); ok {
			pt.FirstError = fe
		}
		if n > 0 {
			fn := float64(n)
			pt.RSSPerConn = (float64(s.RSS) - float64(baseStats.RSS)) / fn
			pt.HeapPerConn = (float64(s.HeapLive) - float64(baseStats.HeapLive)) / fn
			pt.StackPerConn = (float64(s.Stacks) - float64(baseStats.Stacks)) / fn
			pt.GoMappedPerCon = (float64(s.GoMapped) - float64(baseStats.GoMapped)) / fn
			pt.GoroutinesPer = float64(s.Goroutines-baseStats.Goroutines) / fn
		}
		res.Points = append(res.Points, pt)
		logf("    idle %6d/%-6d  open %5.1fs  rss %7.1f MB  %6.1f KB/conn  heap %5.1f KB/conn  stack %5.1f KB/conn  %.2f goroutines/conn  errors %d",
			n, target, open.Seconds(), mb(s.RSS), pt.RSSPerConn/1024, pt.HeapPerConn/1024, pt.StackPerConn/1024, pt.GoroutinesPer, pt.Errors)
		if li == len(levels)-1 && prof != nil {
			prof.fetch(p, "/debug/pprof/heap", "heap-idle.pb.gz")
			prof.fetch(p, "/debug/pprof/goroutine?debug=1", "goroutines-idle.txt")
		}
		if n < target {
			break
		}
	}
	for _, c := range conns {
		c.Close()
	}
	conns = nil
	// Close the client's shared connections too (QUIC, h2): what is left on
	// the server after that is a leak, or a goroutine still winding down.
	c.close()
	time.Sleep(3 * time.Second)
	if s, err := p.stats(true); err == nil {
		res.GoroutinesClosed = s.Goroutines
		res.HeapClosed = s.HeapLive
	}
	return res, nil
}

// --- throughput ----------------------------------------------------------------------

type throughput struct {
	Name       string  `json:"name"`
	Direction  string  `json:"direction"` // down: sink -> client, up: client -> sink
	Streams    int     `json:"streams"`
	Seconds    float64 `json:"seconds"`
	Bytes      int64   `json:"bytes"`
	MBps       float64 `json:"mb_per_s"` // 10^6 bytes per second
	Gbps       float64 `json:"gbit_per_s"`
	ServerCPU  float64 `json:"server_cpu_s"`
	CPUPerGB   float64 `json:"server_cpu_s_per_gb"` // CPU seconds per 10^9 bytes
	Cores      float64 `json:"server_cores"`        // average cores busy
	RSS        uint64  `json:"server_rss"`
	Goroutines int     `json:"server_goroutines"`
	Errors     int     `json:"errors"`
	FirstError string  `json:"first_error,omitempty"`
}

func runThroughput(p *serverProc, c *client, dir byte, streams int, d time.Duration, prof *profiler, profName string) (throughput, error) {
	t := throughput{Streams: streams, Direction: map[byte]string{cmdDownload: "down", cmdUpload: "up"}[dir]}
	t.Name = fmt.Sprintf("%s-%d", t.Direction, streams)
	conns := make([]net.Conn, 0, streams)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i < streams; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		conn, err := c.dial(ctx, i)
		cancel()
		if err != nil {
			return t, err
		}
		if _, err := conn.Write([]byte{dir}); err != nil {
			conn.Close()
			return t, err
		}
		conns = append(conns, conn)
	}
	var total atomic.Int64
	var errCount atomic.Int64
	var firstErr atomic.Value
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			buf := make([]byte, 32*1024)
			for {
				select {
				case <-stop:
					return
				default:
				}
				var n int
				var err error
				if dir == cmdDownload {
					n, err = conn.Read(buf)
				} else {
					n, err = conn.Write(buf)
				}
				total.Add(int64(n))
				if err != nil {
					select {
					case <-stop:
					default:
						if errCount.Add(1) == 1 {
							firstErr.Store(err.Error())
						}
					}
					return
				}
			}
		}(conn)
	}
	// Ramp up before measuring.
	time.Sleep(500 * time.Millisecond)
	s0, err := p.stats(false)
	if err != nil {
		return t, err
	}
	b0 := total.Load()
	t0 := time.Now()
	if prof != nil && d >= 3*time.Second {
		go prof.fetch(p, fmt.Sprintf("/debug/pprof/profile?seconds=%d", int((d-time.Second).Seconds())), "cpu-"+profName+".pb.gz")
	}
	time.Sleep(d)
	s1, err := p.stats(false)
	b1 := total.Load()
	el := time.Since(t0)
	close(stop)
	for _, c := range conns {
		c.Close()
	}
	conns = conns[:0]
	wg.Wait()
	if err != nil {
		return t, err
	}
	t.Seconds = el.Seconds()
	t.Bytes = b1 - b0
	t.MBps = float64(t.Bytes) / t.Seconds / 1e6
	t.Gbps = float64(t.Bytes) * 8 / t.Seconds / 1e9
	t.ServerCPU = s1.CPU() - s0.CPU()
	if t.Bytes > 0 {
		t.CPUPerGB = t.ServerCPU / (float64(t.Bytes) / 1e9)
	}
	t.Cores = t.ServerCPU / t.Seconds
	t.RSS = s1.RSS
	t.Goroutines = s1.Goroutines
	t.Errors = int(errCount.Load())
	if fe, ok := firstErr.Load().(string); ok {
		t.FirstError = fe
	}
	logf("    %-8s %8.1f MB/s  %6.2f Gbit/s  cpu %5.2f s/GB  %4.2f cores  rss %6.1f MB  errors %d",
		t.Name, t.MBps, t.Gbps, t.CPUPerGB, t.Cores, mb(t.RSS), t.Errors)
	return t, nil
}

// --- connection rate --------------------------------------------------------------------

type connRate struct {
	Workers      int     `json:"workers"`
	Seconds      float64 `json:"seconds"`
	Conns        int     `json:"conns"`
	PerSec       float64 `json:"conns_per_s"`
	P50ms        float64 `json:"p50_ms"`
	P99ms        float64 `json:"p99_ms"`
	ServerCPU    float64 `json:"server_cpu_s"`
	CPUmsPer     float64 `json:"server_cpu_ms_per_conn"`
	Cores        float64 `json:"server_cores"`
	RSS          uint64  `json:"server_rss"`
	Errors       int     `json:"errors"`
	FirstError   string  `json:"first_error,omitempty"`
	GoroutineEnd int     `json:"server_goroutines_after"`
}

// oneRequest: new connection, one short request, the sink answers and closes.
func oneRequest(c *client, i int) error {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	conn, err := c.dial(ctx, i)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(dialTimeout))
	if _, err := conn.Write([]byte{cmdRequest, 'h', 'i'}); err != nil {
		return err
	}
	var buf [rateReplySize]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		return err
	}
	// Let the server close first (it got EOF from the sink).
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	io.Copy(io.Discard, conn)
	return nil
}

func runRate(p *serverProc, c *client, workers int, d time.Duration, prof *profiler, profName string) (connRate, error) {
	r := connRate{Workers: workers}
	s0, err := p.stats(false)
	if err != nil {
		return r, err
	}
	if prof != nil && d >= 3*time.Second {
		go prof.fetch(p, fmt.Sprintf("/debug/pprof/profile?seconds=%d", int((d-time.Second).Seconds())), "cpu-"+profName+".pb.gz")
	}
	deadline := time.Now().Add(d)
	t0 := time.Now()
	var errCount atomic.Int64
	var firstErr atomic.Value
	lat := make([][]time.Duration, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; time.Now().Before(deadline); i += workers {
				st := time.Now()
				if err := oneRequest(c, i%workers); err != nil {
					if errCount.Add(1) == 1 {
						firstErr.Store(err.Error())
					}
					if errors.Is(err, context.DeadlineExceeded) {
						continue
					}
					time.Sleep(10 * time.Millisecond)
					continue
				}
				lat[w] = append(lat[w], time.Since(st))
			}
		}(w)
	}
	wg.Wait()
	el := time.Since(t0)
	s1, err := p.stats(false)
	if err != nil {
		return r, err
	}
	var all []time.Duration
	for _, l := range lat {
		all = append(all, l...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	r.Seconds = el.Seconds()
	r.Conns = len(all)
	r.PerSec = float64(r.Conns) / r.Seconds
	if len(all) > 0 {
		r.P50ms = float64(all[len(all)/2]) / 1e6
		r.P99ms = float64(all[len(all)*99/100]) / 1e6
	}
	r.ServerCPU = s1.CPU() - s0.CPU()
	if r.Conns > 0 {
		r.CPUmsPer = r.ServerCPU * 1000 / float64(r.Conns)
	}
	r.Cores = r.ServerCPU / r.Seconds
	r.RSS = s1.RSS
	r.Errors = int(errCount.Load())
	if fe, ok := firstErr.Load().(string); ok {
		r.FirstError = fe
	}
	if prof != nil {
		prof.fetch(p, "/debug/pprof/allocs", "allocs-"+profName+".pb.gz")
	}
	time.Sleep(2 * time.Second)
	if s, err := p.stats(false); err == nil {
		r.GoroutineEnd = s.Goroutines
	}
	logf("    rate     %8.0f conn/s  p50 %6.2f ms  p99 %7.2f ms  cpu %5.3f ms/conn  %4.2f cores  errors %d",
		r.PerSec, r.P50ms, r.P99ms, r.CPUmsPer, r.Cores, r.Errors)
	return r, nil
}

// --- profiles ---------------------------------------------------------------------------

type profiler struct {
	dir    string
	prefix string
}

func (pr *profiler) fetch(p *serverProc, path, name string) {
	if err := os.MkdirAll(pr.dir, 0o755); err != nil {
		logf("    pprof: %v", err)
		return
	}
	if err := p.fetch(path, filepath.Join(pr.dir, pr.prefix+"-"+name)); err != nil {
		logf("    pprof %s: %v", name, err)
	}
}

func mb(b uint64) float64 { return float64(b) / (1 << 20) }
