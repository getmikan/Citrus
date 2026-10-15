package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
)

// serverProc is a Citrus server running as a child process.
type serverProc struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	statsAddr string
	logPath   string
	http      *http.Client
}

// serverHost is where the inbound listens and the client connects: ::1 when
// the machine has it, so that the clients' addresses (::1) never equal the
// local addresses of the server's own DIRECT connections to the sink
// (127.0.0.1). On a single loopback address, a client port that matches the
// port of a live DIRECT connection trips Citrus's loopback detector (a proxy
// loop guard), which rejects the connection; real clients never come from
// the server's own addresses.
var serverHost = "127.0.0.1"

// pickServerHost selects ::1 if it works, otherwise keeps 127.0.0.1 and
// disables the loopback detector in the server process instead.
func pickServerHost() (disableDetector bool) {
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		return true
	}
	l.Close()
	c, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		return true
	}
	c.Close()
	serverHost = "::1"
	return false
}

var disableLoopbackDetector bool

func freePort(udp bool) (int, error) {
	return freePortOn(serverHost, udp)
}

func freePortOn(host string, udp bool) (int, error) {
	if udp {
		c, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
		if err != nil {
			return 0, err
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port, nil
	}
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func startServer(dir string, cfg obj, procs int) (*serverProc, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(dir, "config.yaml") // JSON is YAML
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		return nil, err
	}
	sp, err := freePortOn("127.0.0.1", false)
	if err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	statsAddr := "127.0.0.1:" + strconv.Itoa(sp)
	logPath := filepath.Join(dir, "server.log")
	logf, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(self, "-role", "server", "-config", cfgPath, "-home", dir, "-stats", statsAddr)
	env := os.Environ()
	if procs > 0 {
		env = append(env, "GOMAXPROCS="+strconv.Itoa(procs))
	}
	if disableLoopbackDetector {
		env = append(env, "DISABLE_LOOPBACK_DETECTOR=true")
	}
	cmd.Env = env
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = logf
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &serverProc{cmd: cmd, stdin: stdin, statsAddr: statsAddr, logPath: logPath,
		http: &http.Client{Timeout: 120 * time.Second}}
	ready := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		ok := false
		for sc.Scan() {
			line := sc.Text()
			fmt.Fprintln(logf, line)
			if !ok && line == "ready" {
				ok = true
				ready <- true
			}
		}
		if !ok {
			ready <- false
		}
	}()
	select {
	case ok := <-ready:
		if !ok {
			p.stop()
			return nil, fmt.Errorf("server exited: %s", tail(logPath))
		}
	case <-time.After(60 * time.Second):
		p.stop()
		return nil, fmt.Errorf("server not ready after 60s: %s", tail(logPath))
	}
	return p, nil
}

func tail(path string) string {
	b, _ := os.ReadFile(path)
	s := strings.TrimSpace(string(b))
	if len(s) > 2000 {
		s = s[len(s)-2000:]
	}
	return s
}

func (p *serverProc) stop() {
	p.stdin.Close()
	done := make(chan struct{})
	go func() { p.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		p.cmd.Process.Kill()
		<-done
	}
}

func (p *serverProc) stats(gc bool) (serverStats, error) {
	var s serverStats
	u := "http://" + p.statsAddr + "/stats"
	if gc {
		u += "?gc=1"
	}
	resp, err := p.http.Get(u)
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()
	return s, json.NewDecoder(resp.Body).Decode(&s)
}

// fetch saves a /debug/pprof resource to a file.
func (p *serverProc) fetch(path, file string) error {
	resp, err := p.http.Get("http://" + p.statsAddr + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", path, resp.Status)
	}
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// --- client --------------------------------------------------------------------

// client dials the sink through the server with Citrus outbounds.
type client struct {
	mapping        obj
	streamsPerConn int
	md             *C.Metadata

	mu      sync.Mutex
	proxies []C.Proxy
}

func newClient(s *scenario, m *material, port int, sink netip.AddrPort) *client {
	mp := s.proxy(m, port)
	mp["name"] = "bench-out"
	return &client{
		mapping:        mp,
		streamsPerConn: s.streamsPerConn,
		md:             &C.Metadata{NetWork: C.TCP, Type: C.INNER, DstIP: sink.Addr(), DstPort: sink.Port()},
	}
}

// proxy returns the outbound for the i-th connection.
func (c *client) proxy(i int) (C.Proxy, error) {
	idx := 0
	if c.streamsPerConn > 0 {
		idx = i / c.streamsPerConn
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.proxies) <= idx {
		mp := make(obj, len(c.mapping))
		for k, v := range c.mapping {
			mp[k] = v
		}
		p, err := adapter.ParseProxy(mp)
		if err != nil {
			return nil, err
		}
		c.proxies = append(c.proxies, p)
	}
	return c.proxies[idx], nil
}

func (c *client) dial(ctx context.Context, i int) (net.Conn, error) {
	p, err := c.proxy(i)
	if err != nil {
		return nil, err
	}
	md := *c.md
	return p.DialContext(ctx, &md)
}

func (c *client) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range c.proxies {
		p.Close()
	}
	c.proxies = nil
}
