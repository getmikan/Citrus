package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const dialTimeout = 15 * time.Second

// dialer opens tunnels to the sink through the client's SOCKS5 inbound.
type dialer struct {
	socks   string      // 127.0.0.1:port of the client
	tlsIn   *tls.Config // wrap the tunnel in TLS 1.3 to the sink (inner-TLS variant)
	dstPort int
}

// newDialer: with roots set, tunnels carry TLS 1.3 to the sink inside.
func newDialer(socksPort int, roots *x509.CertPool) *dialer {
	d := &dialer{socks: fmt.Sprintf("127.0.0.1:%d", socksPort), dstPort: sinkPort}
	if roots != nil {
		d.dstPort = sinkTLS
		d.tlsIn = &tls.Config{ServerName: benchSNI, RootCAs: roots, MinVersion: tls.VersionTLS13}
	}
	return d
}

// open dials a tunnel and sends the sink command (and its argument).
func (d *dialer) open(cmd byte, arg []byte) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	c, err := socksConnect(ctx, d.socks, net.ParseIP(sinkIP).To4(), d.dstPort)
	if err != nil {
		return nil, err
	}
	if d.tlsIn != nil {
		tc := tls.Client(c, d.tlsIn)
		tc.SetDeadline(time.Now().Add(dialTimeout))
		if err := tc.Handshake(); err != nil {
			c.Close()
			return nil, fmt.Errorf("inner tls: %w", err)
		}
		// the sink's ready byte: the Finished flight has gone through (see handleSinkTLS)
		if err := readReady(tc); err != nil {
			c.Close()
			return nil, fmt.Errorf("inner tls ready: %w", err)
		}
		tc.SetDeadline(time.Time{})
		c = tc
	}
	if _, err := c.Write(append([]byte{cmd}, arg...)); err != nil {
		c.Close()
		return nil, err
	}
	if d.tlsIn != nil && cmd == cmdUpload {
		// the sink's ack: the command record went through alone, before any data
		c.SetDeadline(time.Now().Add(dialTimeout))
		if err := readReady(c); err != nil {
			c.Close()
			return nil, fmt.Errorf("upload ack: %w", err)
		}
		c.SetDeadline(time.Time{})
	}
	return c, nil
}

func readReady(c net.Conn) error {
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return err
	}
	if b[0] != sinkReady {
		return fmt.Errorf("got %q, want %q", b[0], sinkReady)
	}
	return nil
}

// socksConnect does a SOCKS5 CONNECT (no auth) to ip:port.
func socksConnect(ctx context.Context, proxy string, ip net.IP, port int) (net.Conn, error) {
	var nd net.Dialer
	c, err := nd.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	req := []byte{5, 1, 0, 5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	// method reply (VER METHOD), then the connect reply (VER REP RSV ATYP ...)
	var resp [6]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks: %w", err)
	}
	if resp[0] != 5 || resp[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("socks: method reply %v", resp[:2])
	}
	if resp[3] != 0 {
		c.Close()
		return nil, fmt.Errorf("socks: connect reply %d", resp[3])
	}
	var rest int
	switch resp[5] {
	case 1:
		rest = 4 + 2
	case 4:
		rest = 16 + 2
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			c.Close()
			return nil, err
		}
		rest = int(l[0]) + 2
	default:
		c.Close()
		return nil, fmt.Errorf("socks: address type %d", resp[5])
	}
	if _, err := io.CopyN(io.Discard, c, int64(rest)); err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

func u64(v int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}

type countWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

func waitTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("nothing listens on %s after %s", addr, timeout)
}

// --- cgroup v2 of a container, read through the host's /sys/fs/cgroup -----------

type cgroup struct{ dir string }

func (g cgroup) read(name string) (string, error) {
	b, err := os.ReadFile(g.dir + "/" + name)
	return string(b), err
}

// cpu returns the cumulative CPU time of the cgroup.
func (g cgroup) cpu() time.Duration {
	if g.dir == "" {
		return 0
	}
	s, err := g.read("cpu.stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, "usage_usec "); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return time.Duration(n) * time.Microsecond
		}
	}
	return 0
}

func (g cgroup) memCurrent() uint64 {
	s, _ := g.read("memory.current")
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return n
}

func (g cgroup) memStat(key string) uint64 {
	s, _ := g.read("memory.stat")
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, key+" "); ok {
			n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return 0
}

func (g cgroup) pids() []int {
	s, _ := g.read("cgroup.procs")
	var out []int
	for _, f := range strings.Fields(s) {
		if n, err := strconv.Atoi(f); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// rss is the sum of VmRSS of the cgroup's processes (needs --pid=host).
func (g cgroup) rss() uint64 {
	var total uint64
	for _, pid := range g.pids() {
		f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "VmRSS:"); ok {
				kb, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
				total += kb * 1024
			}
		}
		f.Close()
	}
	return total
}

// ncpu counts cpuset.cpus.effective ("2-3", "6-19,22").
func (g cgroup) ncpu() int {
	s, err := g.read("cpuset.cpus.effective")
	if err != nil {
		return 0
	}
	n := 0
	for _, part := range strings.Split(strings.TrimSpace(s), ",") {
		if part == "" {
			continue
		}
		a, b, ok := strings.Cut(part, "-")
		x, _ := strconv.Atoi(a)
		y := x
		if ok {
			y, _ = strconv.Atoi(b)
		}
		n += y - x + 1
	}
	return n
}

// --- TLS key share probe ---------------------------------------------------------

// keyShareRelay forwards one connection to upstream and reports the key share
// group of the server's ServerHello (plaintext in TLS 1.3).
func keyShareRelay(upstream string) (addr string, result <-chan string, err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	ch := make(chan string, 1)
	go func() {
		defer ln.Close()
		c, err := ln.Accept()
		if err != nil {
			ch <- "accept: " + err.Error()
			return
		}
		defer c.Close()
		u, err := net.DialTimeout("tcp", upstream, 5*time.Second)
		if err != nil {
			ch <- "dial: " + err.Error()
			return
		}
		defer u.Close()
		go io.Copy(u, c)
		br := bufio.NewReader(u)
		ch <- parseServerHello(br)
		io.Copy(c, br)
	}()
	return ln.Addr().String(), ch, nil
}

var groupNames = map[uint16]string{
	0x001d: "X25519", 0x0017: "P-256", 0x0018: "P-384", 0x11ec: "X25519MLKEM768",
	0x6399: "X25519Kyber768Draft00",
}

func parseServerHello(r *bufio.Reader) string {
	hdr, err := r.Peek(5)
	if err != nil {
		return "no record: " + err.Error()
	}
	if hdr[0] != 22 {
		return fmt.Sprintf("first record type %d", hdr[0])
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	rec, err := r.Peek(5 + n)
	if err != nil {
		return "short record"
	}
	b := rec[5:]
	if len(b) < 4 || b[0] != 2 {
		return "not a ServerHello"
	}
	b = b[4:]
	if len(b) < 2+32+1 {
		return "short ServerHello"
	}
	b = b[34:]
	sid := int(b[0])
	if len(b) < 1+sid+3+2 {
		return "short ServerHello"
	}
	b = b[1+sid+3:]
	el := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if len(b) < el {
		return "short extensions"
	}
	b = b[:el]
	for len(b) >= 4 {
		typ, l := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		if len(b) < 4+l {
			break
		}
		if typ == 0x0033 && l >= 2 {
			g := binary.BigEndian.Uint16(b[4:])
			if name, ok := groupNames[g]; ok {
				return name
			}
			return fmt.Sprintf("0x%04x", g)
		}
		b = b[4+l:]
	}
	return "no key_share"
}

var errStopped = errors.New("stopped")
