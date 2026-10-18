//go:build interop

package interop

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	realitySNI = "interop.test"     // REALITY server name and TLS/ECH inner name
	echPublic  = "ech.interop.test" // ECH outer (public) name
	shortID    = "0123456789abcdef"
)

var (
	xrayBin   string
	mihomoBin string // upstream mihomo release binary, the client of mihomo_test.go
	citrusBin string
	workDir   string
	logDir    string

	echoAddr      string // plain HTTP echo server, the destination of every request
	udpEchoAddr   string // UDP echo server, the destination of the UDP checks
	targetAddr    string // TLS 1.3 server used as REALITY target
	targetCertMsg int    // size of the target's certificate chain, bytes

	tlsCertPEM, tlsKeyPEM []byte // self-signed leaf for interop.test (ECH cases)
	tlsCertSHA256         string // hex SHA-256 of its DER
)

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	xrayBin, mihomoBin = os.Getenv("XRAY_BIN"), os.Getenv("MIHOMO_BIN")
	if xrayBin == "" && mihomoBin == "" {
		fmt.Println("neither XRAY_BIN nor MIHOMO_BIN is set: interop tests are skipped")
		return m.Run()
	}
	var err error
	if workDir, err = os.MkdirTemp("", "citrus-interop-"); err != nil {
		return fail(err)
	}
	defer os.RemoveAll(workDir)
	logDir = os.Getenv("INTEROP_LOG_DIR")
	if logDir == "" {
		logDir = filepath.Join(workDir, "logs")
	}
	if logDir, err = filepath.Abs(logDir); err != nil {
		return fail(err)
	}
	if err = os.MkdirAll(logDir, 0o755); err != nil {
		return fail(err)
	}

	if xrayBin != "" {
		if xrayBin, err = filepath.Abs(xrayBin); err != nil {
			return fail(err)
		}
		out, err := exec.Command(xrayBin, "version").CombinedOutput()
		if err != nil {
			return fail(fmt.Errorf("xray version: %v\n%s", err, out))
		}
		fmt.Print(firstLine(string(out)), "\n")
	}
	if mihomoBin != "" {
		if mihomoBin, err = filepath.Abs(mihomoBin); err != nil {
			return fail(err)
		}
		out, err := exec.Command(mihomoBin, "-v").CombinedOutput()
		if err != nil {
			return fail(fmt.Errorf("mihomo -v: %v\n%s", err, out))
		}
		fmt.Print("client: ", firstLine(string(out)), "\n")
	}

	citrusBin = os.Getenv("CITRUS_BIN")
	if citrusBin == "" {
		citrusBin = filepath.Join(workDir, "citrus"+exeSuffix())
		start := time.Now()
		cmd := exec.Command("go", "build", "-trimpath", "-o", citrusBin, ".")
		cmd.Dir = filepath.Join("..", "..")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fail(fmt.Errorf("go build citrus: %v\n%s", err, out))
		}
		fmt.Printf("built citrus in %s\n", time.Since(start).Round(time.Second))
	} else if citrusBin, err = filepath.Abs(citrusBin); err != nil {
		return fail(err)
	}
	out, err := exec.Command(citrusBin, "-v").CombinedOutput()
	if err != nil {
		return fail(fmt.Errorf("citrus -v: %v\n%s", err, out))
	}
	fmt.Print(firstLine(string(out)), "\n")

	stopEcho, err := startEcho()
	if err != nil {
		return fail(err)
	}
	defer stopEcho()
	stopUDPEcho, err := startUDPEcho()
	if err != nil {
		return fail(err)
	}
	defer stopUDPEcho()
	stopTarget, err := startTarget()
	if err != nil {
		return fail(err)
	}
	defer stopTarget()
	if tlsCertPEM, tlsKeyPEM, tlsCertSHA256, err = leafCert(realitySNI); err != nil {
		return fail(err)
	}
	return m.Run()
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "interop setup:", err)
	return 1
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return strings.TrimSpace(s)
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func needXray(t *testing.T) {
	t.Helper()
	if xrayBin == "" {
		t.Skip("XRAY_BIN is not set")
	}
}

// --- local servers -----------------------------------------------------------

// startEcho serves GET /ping?t=X -> "pong X" and POST /sum -> hex SHA-256 of the body.
func startEcho() (func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	echoAddr = ln.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "pong %s", r.URL.Query().Get("t"))
	})
	mux.HandleFunc("/sum", func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		if _, err := io.Copy(h, r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		io.WriteString(w, hex.EncodeToString(h.Sum(nil)))
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	return func() { srv.Close() }, nil
}

// startUDPEcho sends every datagram back to where it came from.
func startUDPEcho() (func(), error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	udpEchoAddr = pc.LocalAddr().String()
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()
	return func() { pc.Close() }, nil
}

// startTarget runs the REALITY target: TLS 1.3 only, h2 + http/1.1, with a
// root -> intermediate -> leaf chain padded with SANs so that its Certificate
// message is well over the ~3.5 KB that an ML-DSA-65 signature needs.
func startTarget() (func(), error) {
	chain, key, err := bigChain()
	if err != nil {
		return nil, err
	}
	for _, c := range chain {
		targetCertMsg += len(c)
	}
	if targetCertMsg < 4096 {
		return nil, fmt.Errorf("target chain is only %d bytes", targetCertMsg)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	targetAddr = ln.Addr().String()
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "reality target\n")
		}),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}},
		},
		ReadHeaderTimeout: 10 * time.Second,
		// probes and REALITY's own handshakes end in errors here; not interesting
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go srv.ServeTLS(ln, "", "")
	return func() { srv.Close() }, nil
}

func bigChain() ([][]byte, *ecdsa.PrivateKey, error) {
	now := time.Now()
	mk := func(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ca bool, sans []string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		tpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: cn, Organization: []string{"Citrus interop"}},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  ca,
			DNSNames:              sans,
		}
		if ca {
			tpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		} else {
			tpl.KeyUsage = x509.KeyUsageDigitalSignature
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		if parent == nil {
			parent, parentKey = tpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			return nil, nil, err
		}
		c, err := x509.ParseCertificate(der)
		return c, key, err
	}
	root, rootKey, err := mk("Citrus Interop Root", nil, nil, true, nil)
	if err != nil {
		return nil, nil, err
	}
	inter, interKey, err := mk("Citrus Interop Intermediate", root, rootKey, true, nil)
	if err != nil {
		return nil, nil, err
	}
	sans := []string{realitySNI}
	for i := 0; len(sans) < 120; i++ {
		sans = append(sans, fmt.Sprintf("host-%03d.%s", i, realitySNI))
	}
	leaf, leafKey, err := mk(realitySNI, inter, interKey, false, sans)
	if err != nil {
		return nil, nil, err
	}
	return [][]byte{leaf.Raw, inter.Raw, root.Raw}, leafKey, nil
}

// leafCert makes a self-signed certificate for name, for the plain TLS + ECH cases.
func leafCert(name string) (certPEM, keyPEM []byte, sum string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}
	h := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}),
		hex.EncodeToString(h[:]), nil
}

// --- keys from xray ----------------------------------------------------------

func xrayOut(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(xrayBin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("xray %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// field returns the value after "label:" on the same line, or on the next
// non-empty line when the label line has nothing after the colon.
func field(t *testing.T, out, label string) string {
	t.Helper()
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	found := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if found {
			if line != "" {
				return line
			}
			continue
		}
		if v, ok := strings.CutPrefix(line, label+":"); ok {
			if v = strings.TrimSpace(v); v != "" {
				return v
			}
			found = true
		}
	}
	t.Fatalf("no %q in xray output:\n%s", label, out)
	return ""
}

type x25519Keys struct{ priv, pub string }

func genX25519(t *testing.T) x25519Keys {
	out := xrayOut(t, "x25519")
	return x25519Keys{priv: field(t, out, "PrivateKey"), pub: field(t, out, "Password (PublicKey)")}
}

type mldsaKeys struct{ seed, verify string }

func genMLDSA65(t *testing.T) mldsaKeys {
	out := xrayOut(t, "mldsa65")
	return mldsaKeys{seed: field(t, out, "Seed"), verify: field(t, out, "Verify")}
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func genUUID(t *testing.T) string {
	u := strings.TrimSpace(xrayOut(t, "uuid"))
	if !uuidRE.MatchString(u) {
		t.Fatalf("xray uuid: %q", u)
	}
	return u
}

type echKeys struct{ configList, serverKeys string }

func genECH(t *testing.T, publicName string) echKeys {
	out := xrayOut(t, "tls", "ech", "--serverName", publicName)
	return echKeys{configList: field(t, out, "ECH config list"), serverKeys: field(t, out, "ECH server keys")}
}

// --- processes ---------------------------------------------------------------

// handedOut holds every port freePort has returned in this run.
var handedOut = struct {
	sync.Mutex
	ports map[int]bool
}{ports: map[int]bool{}}

// freePort returns a localhost port free for both TCP and UDP (Citrus' mixed
// port binds both; on Windows some ports are reserved for one of them only).
//
// The probe sockets are closed before the port is used, so the OS may offer
// the same port again to the next call: a case that takes two ports before
// starting anything (a listener and a controller, say) could get one port
// twice. A port is therefore never handed out twice in a run.
func freePort(t *testing.T) int {
	t.Helper()
	for range 50 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		ln.Close()
		if err != nil {
			continue
		}
		pc.Close()
		handedOut.Lock()
		taken := handedOut.ports[port]
		handedOut.ports[port] = true
		handedOut.Unlock()
		if !taken {
			return port
		}
	}
	t.Fatal("no free TCP+UDP port")
	return 0
}

func caseName(t *testing.T) string {
	return strings.NewReplacer("/", "__", " ", "_", "?", "_", "=", "_").Replace(t.Name())
}

// start runs bin with args, logging to <logDir>/<test>-<role>.log, and kills it
// when the test ends. On failure the log tail is printed.
// start runs bin and returns the path of its log.
func start(t *testing.T, role, bin string, args ...string) string {
	t.Helper()
	logPath := filepath.Join(logDir, caseName(t)+"-"+role+".log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		f.Close()
		t.Fatalf("start %s: %v", role, err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		f.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logPath)
			lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
			if len(lines) > 40 {
				lines = lines[len(lines)-40:]
			}
			t.Logf("--- %s (%s), last lines:\n%s", role, logPath, strings.Join(lines, "\n"))
		}
	})
	return logPath
}

// waitLog waits until the log at path contains marker.
func waitLog(t *testing.T, path, marker string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && strings.Contains(string(b), marker) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never logged %q", path, marker)
}

func waitPort(t *testing.T, port int) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("nothing listens on %s", addr)
}

func caseDir(t *testing.T, role string) string {
	t.Helper()
	d := filepath.Join(workDir, caseName(t), role)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	// keep a copy next to the logs, handy when a CI run fails
	os.WriteFile(filepath.Join(logDir, caseName(t)+"-"+filepath.Base(filepath.Dir(path))+"-"+filepath.Base(path)), b, 0o644)
}

func writeFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type obj = map[string]any

// startXray writes cfg and runs xray; waits for port.
func startXray(t *testing.T, role string, cfg obj, port int) {
	t.Helper()
	dir := caseDir(t, role)
	p := filepath.Join(dir, "config.json")
	writeJSON(t, p, cfg)
	start(t, role, xrayBin, "run", "-c", p)
	waitPort(t, port)
}

// startCitrus writes cfg (JSON is valid YAML) and runs citrus; waits for port.
// It returns the path of the log.
func startCitrus(t *testing.T, role string, cfg obj, port int) string {
	t.Helper()
	dir := caseDir(t, role)
	p := filepath.Join(dir, "config.yaml")
	writeJSON(t, p, cfg)
	logPath := start(t, role, citrusBin, "-d", dir, "-f", p)
	waitPort(t, port)
	// Citrus opens its listeners before the tunnel is running: providers load
	// in between, and connections that arrive then are dropped (EOF). Wait for
	// the provider step, then give the tunnel a moment to switch to running,
	// so neither a pass nor an "expected rejection" comes from startup.
	waitLog(t, logPath, "Start initial compatible provider")
	time.Sleep(300 * time.Millisecond)
	// A listener that failed to bind leaves the case testing something else
	// (another process answering on its port), so stop here with the reason.
	if b, err := os.ReadFile(logPath); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "listen err") {
				t.Fatalf("%s: a listener did not start: %s", role, line)
			}
		}
	}
	return logPath
}

// xrayFreedom is a freedom outbound that may reach 127.0.0.1: since v26 Xray
// blocks private destinations for vless/vmess/trojan/... inbounds unless a
// final rule allows them.
func xrayFreedom() obj {
	return obj{"protocol": "freedom", "settings": obj{"finalRules": []obj{{"action": "allow"}}}}
}

func xraySocksIn(port int) obj {
	return obj{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": obj{"udp": false}}
}

func xrayLog() obj { return obj{"loglevel": "debug"} }

// citrusClient is a Citrus config with a socks/http mixed port and one proxy.
func citrusClient(mixedPort int, proxy obj) obj {
	proxy["name"] = "x"
	return obj{
		"log-level":  "debug",
		"ipv6":       false,
		"allow-lan":  false,
		"mixed-port": mixedPort,
		"proxies":    []obj{proxy},
		"rules":      []string{"MATCH,x"},
	}
}

func citrusServer(listener obj) obj {
	return obj{
		"log-level": "debug",
		"ipv6":      false,
		"listeners": []obj{listener},
		"rules":     []string{"MATCH,DIRECT"},
	}
}

// --- traffic -----------------------------------------------------------------

func socksClient(port int, timeout time.Duration) *http.Client {
	u := &url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", port)}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true},
	}
}

func token() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// checkTraffic sends a GET and a 256 KiB POST through the socks proxy on port.
func checkTraffic(t *testing.T, port int) {
	t.Helper()
	c := socksClient(port, 20*time.Second)
	tok := token()
	resp, err := c.Get("http://" + echoAddr + "/ping?t=" + tok)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "pong "+tok {
		t.Fatalf("GET through proxy: %q, %v", body, err)
	}

	blob := make([]byte, 256*1024)
	rand.Read(blob)
	sum := sha256.Sum256(blob)
	resp, err = c.Post("http://"+echoAddr+"/sum", "application/octet-stream", bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("POST 256 KiB through proxy: %v", err)
	}
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != hex.EncodeToString(sum[:]) {
		t.Fatalf("POST 256 KiB through proxy: got %q, %v", body, err)
	}
}

// checkBlocked expects a request through the proxy on port not to get through.
func checkBlocked(t *testing.T, port int) {
	t.Helper()
	c := socksClient(port, 8*time.Second)
	tok := token()
	resp, err := c.Get("http://" + echoAddr + "/ping?t=" + tok)
	if err != nil {
		t.Logf("rejected as expected: %v", err)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(body), tok) {
		t.Fatalf("traffic went through, expected a rejection (status %d)", resp.StatusCode)
	}
	t.Logf("rejected as expected: status %d", resp.StatusCode)
}
