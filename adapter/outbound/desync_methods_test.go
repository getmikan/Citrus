package outbound

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	"github.com/Nemu-x/desync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func randomCut(from, to string, count, minPiece int) DesyncRandomCut {
	return DesyncRandomCut{From: from, To: to, Count: count, MinPiece: minPiece}
}

// Options that are wrong on every OS.
func TestDesyncMethodOptionValidation(t *testing.T) {
	manyRanges := make([]DesyncRandomCut, 17)
	for i := range manyRanges {
		manyRanges[i] = randomCut("1", "50", 1, 1)
	}
	for name, option := range map[string]DesyncOption{
		"split-wait unknown":       {Split: "2", SplitWait: "later"},
		"split-wait without split": {TLSRec: "1+s", SplitWait: "acked"},
		"split-wait-timeout alone": {Split: "2", SplitWaitTimeout: 100},
		"split-wait-timeout long":  {Split: "2", SplitWait: "acked", SplitWaitTimeout: 60001},
		"split-wait-timeout neg":   {Split: "2", SplitWait: "acked", SplitWaitTimeout: -1},
		"disorder without split":   {TLSRec: "1+s", Disorder: true},
		"disorder acked":           {Split: "2", Disorder: true, SplitWait: "acked"},
		"oob without split":        {TLSRec: "1+s", OOB: true},
		"oob-byte without oob":     {Split: "2", OOBByte: "x"},
		"oob-byte two characters":  {Split: "2", OOB: true, OOBByte: "ab"},
		"oob-byte not ascii":       {Split: "2", OOB: true, OOBByte: "é"},
		"random empty":             {Random: &DesyncRandomOption{Seed: 1}},
		"random bad from":          {Random: &DesyncRandomOption{TLSRec: []DesyncRandomCut{randomCut("x", "3", 1, 1)}}},
		"random bad to":            {Random: &DesyncRandomOption{Split: []DesyncRandomCut{randomCut("1", "3+q", 1, 1)}}},
		"random missing to":        {Random: &DesyncRandomOption{Split: []DesyncRandomCut{{From: "1"}}}},
		"random reversed":          {Random: &DesyncRandomOption{TLSRec: []DesyncRandomCut{randomCut("8", "3", 1, 1)}}},
		"random mixed anchors":     {Random: &DesyncRandomOption{TLSRec: []DesyncRandomCut{randomCut("1", "3+s", 1, 1)}}},
		"random count":             {Random: &DesyncRandomOption{Split: []DesyncRandomCut{randomCut("1", "90", 65, 1)}}},
		"random negative count":    {Random: &DesyncRandomOption{Split: []DesyncRandomCut{randomCut("1", "90", -1, 1)}}},
		"random min-piece":         {Random: &DesyncRandomOption{Split: []DesyncRandomCut{randomCut("1", "90", 1, 1<<20)}}},
		"random too many ranges":   {Random: &DesyncRandomOption{TLSRec: manyRanges}},
		"split-delay random tlsrec": {
			Random: &DesyncRandomOption{TLSRec: []DesyncRandomCut{randomCut("1", "90", 1, 1)}}, SplitDelay: 5,
		},
		"fake without ttl":      {TLSRec: "1+s", Fake: &DesyncFakeOption{}},
		"fake negative ttl":     {TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: -1, AutoTTL: &DesyncAutoTTLOption{}}},
		"fake auto-ttl delta":   {TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4, AutoTTL: &DesyncAutoTTLOption{Delta: 255}}},
		"fake auto-ttl min>max": {TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4, AutoTTL: &DesyncAutoTTLOption{Min: 10, Max: 5}}},
		"fake auto-ttl max":     {TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4, AutoTTL: &DesyncAutoTTLOption{Max: 256}}},
		"fake sni ip":           {TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4, SNI: []string{"192.0.2.1"}}},
		"fake sni invalid":      {TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4, SNI: []string{"bad_name!"}}},
		"fake from-original":    {TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4, FromOriginal: true}},
		"fake offset negative":  {TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4, Offset: -1}},
		"fake offset large":     {TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4, Offset: 1 << 16}},
		"fake split acked":      {Split: "2", SplitWait: "acked", Fake: &DesyncFakeOption{TTL: 4}},
		"udp template":          {UDP: &DesyncUDPOption{TTL: 4, Template: "dns"}},
		"udp sni without quic":  {UDP: &DesyncUDPOption{TTL: 4, SNI: "www.example.com"}},
		"udp sni invalid":       {UDP: &DesyncUDPOption{TTL: 4, Template: "quic", SNI: "bad_name!"}},
	} {
		option.Name = name
		_, err := NewDesync(option)
		assert.Error(t, err, name)
		if err != nil {
			assert.Contains(t, err.Error(), `desync "`+name+`"`, "the error names the outbound")
		}
	}

	// Valid on every OS.
	for name, option := range map[string]DesyncOption{
		"random tlsrec": {Random: &DesyncRandomOption{TLSRec: []DesyncRandomCut{randomCut("-8+s", "8+s", 2, 2)}}},
		"random split":  {Random: &DesyncRandomOption{Split: []DesyncRandomCut{randomCut("1", "120", 0, 0)}, Seed: 7}, SplitDelay: 5},
		"random both":   {TLSRec: "1+s", Split: "3", Random: &DesyncRandomOption{TLSRec: []DesyncRandomCut{randomCut("1", "40", 3, 4)}, Split: []DesyncRandomCut{randomCut("-4+s", "4+s", 1, 1)}}},
	} {
		option.Name = name
		_, err := NewDesync(option)
		assert.NoError(t, err, name)
	}
}

// The socket methods are accepted where this OS implements them and are
// otherwise errors that name the OS and wrap the library's error.
func TestDesyncMethodsOnThisOS(t *testing.T) {
	caps := desync.PlatformCapabilities()
	// Android lists these as conditional: accepted, decided per socket.
	sent := caps.Ack.Sent || desyncConditional(caps, "split-wait-sent")
	disorder := caps.Disorder.Supported || desyncConditional(caps, "disorder")
	fake := caps.FakeTCP || desyncConditional(caps, "fake-tcp")
	for _, tc := range []struct {
		name      string
		option    DesyncOption
		supported bool
		sentinel  error
	}{
		{"disorder", DesyncOption{Split: "1+s", Disorder: true, SplitWaitTimeout: 500}, disorder, desync.ErrDisorderUnsupported},
		{"oob", DesyncOption{Split: "1+s", OOB: true, OOBByte: "z"}, caps.OOB, desync.ErrOOBUnsupported},
		{"disoob", DesyncOption{Split: "1+s", Disorder: true, OOB: true}, disorder && caps.OOB, nil},
		{"split-wait sent", DesyncOption{Split: "1+s", SplitWait: "sent"}, sent, desync.ErrSplitWaitUnsupported},
		{"split-wait acked", DesyncOption{Split: "1+s", SplitWait: "acked", SplitWaitTimeout: 1000}, caps.Ack.Acked, desync.ErrSplitWaitUnsupported},
		{"fake decoy", DesyncOption{TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4, SNI: []string{"www.example.com", "cdn-##.example.net"}, Randomize: true, Offset: 2}}, fake, desync.ErrFakeUnsupported},
		{"fake from-original", DesyncOption{Fake: &DesyncFakeOption{TTL: 4, SNI: []string{"www.example.com"}, FromOriginal: true}}, fake, desync.ErrFakeUnsupported},
		{"fake with split", DesyncOption{Split: "1+s", Disorder: true, Fake: &DesyncFakeOption{TTL: 4}}, fake, desync.ErrFakeUnsupported},
		{"fake random split", DesyncOption{Random: &DesyncRandomOption{Split: []DesyncRandomCut{randomCut("1", "8", 1, 1)}}, Fake: &DesyncFakeOption{TTL: 4}}, fake, desync.ErrFakeUnsupported},
		{"fake auto-ttl fallback", DesyncOption{TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4, AutoTTL: &DesyncAutoTTLOption{Delta: 2, Min: 2, Max: 30}}}, fake, desync.ErrFakeUnsupported},
		{"fake auto-ttl only", DesyncOption{TLSRec: "1+s", Fake: &DesyncFakeOption{AutoTTL: &DesyncAutoTTLOption{}}}, fake && (caps.AutoTTL.IPv4 || caps.AutoTTL.IPv6), nil},
		{"udp quic", DesyncOption{UDP: &DesyncUDPOption{TTL: 4, Template: "quic", SNI: "www.example.com", QUICOnly: true}}, caps.FakeUDP, desync.ErrUDPFakeUnsupported},
		{"udp quic-only zero", DesyncOption{UDP: &DesyncUDPOption{TTL: 4, Template: "zero", QUICOnly: true}}, caps.FakeUDP, desync.ErrUDPFakeUnsupported},
	} {
		tc.option.Name = tc.name
		_, err := NewDesync(tc.option)
		if tc.supported {
			assert.NoError(t, err, tc.name)
			continue
		}
		if assert.Error(t, err, tc.name) {
			assert.Contains(t, err.Error(), runtime.GOOS, tc.name)
			if tc.sentinel != nil {
				assert.ErrorIs(t, err, tc.sentinel, tc.name)
			}
		}
	}
}

// What PlatformCapabilities reports for macOS, Windows, Linux and an OS
// without any socket method in v0.1.0, so that each per-OS error is checked
// on any OS.
var (
	desyncCapsDarwin = desync.Capabilities{
		OS: "darwin", FakeUDP: true, TTLControl: true, OOB: true,
		Disorder: desync.DisorderCapability{Supported: true, Mechanism: "SO_NWRITE"},
		Ack:      desync.AckCapability{Mechanism: "SO_NWRITE", Acked: true, Reliable: true},
		Unsupported: map[string]string{
			"fake-tcp":      "no splice: sendfile copies the data into the socket buffer, so a retransmission cannot carry the original bytes",
			"auto-ttl-ipv4": "xnu TCP keeps no received IP control data",
			"auto-ttl-ipv6": "xnu TCP keeps no received IP control data",
		},
	}
	desyncCapsWindows = desync.Capabilities{
		OS: "windows", FakeTCP: true, FakeUDP: true, TTLControl: true, OOB: true,
		Disorder: desync.DisorderCapability{Supported: true, Mechanism: "SIO_TCP_INFO", Observed: true},
		Ack:      desync.AckCapability{Mechanism: "SIO_TCP_INFO", Sent: true, Acked: true},
		Unsupported: map[string]string{
			"auto-ttl-ipv4": "Winsock reports a received TTL only through WSARecvMsg control data",
			"auto-ttl-ipv6": "Winsock reports a received TTL only through WSARecvMsg control data",
		},
	}
	desyncCapsLinux = desync.Capabilities{
		OS: "linux", FakeTCP: true, FakeUDP: true, TTLControl: true, OOB: true,
		Disorder: desync.DisorderCapability{Supported: true, Mechanism: "SIOCOUTQNSD", Observed: true, Reliable: true},
		Ack:      desync.AckCapability{Mechanism: "SIOCOUTQ/SIOCOUTQNSD", Sent: true, Acked: true, Reliable: true},
		AutoTTL:  desync.AutoTTLCapability{Mechanism: "IPV6_RECVHOPLIMIT/IPV6_2292PKTOPTIONS", IPv6: true},
		Unsupported: map[string]string{
			"auto-ttl-ipv4": "Linux records no received TTL for an outgoing IPv4 TCP connection",
		},
	}
	// Android in v0.2.1: SIOCOUTQNSD is denied to apps, so the methods that
	// need unsent bytes are not claimed but listed in Conditional (and in
	// Unsupported); a socket decides them through TCP_INFO.
	desyncCapsAndroid = desync.Capabilities{
		OS: "android", FakeUDP: true, TTLControl: true, OOB: true,
		Ack:     desync.AckCapability{Mechanism: "SIOCOUTQ", Acked: true, Reliable: true},
		AutoTTL: desync.AutoTTLCapability{Mechanism: "IPV6_RECVHOPLIMIT/IPV6_2292PKTOPTIONS", IPv6: true},
		Unsupported: map[string]string{
			"auto-ttl-ipv4":   "Linux records no received TTL for an outgoing IPv4 TCP connection",
			"split-wait-sent": desyncAndroidReason,
			"fake-tcp":        desyncAndroidReason,
			"disorder":        desyncAndroidReason,
		},
		Conditional: map[string]string{
			"split-wait-sent": desyncAndroidReason,
			"fake-tcp":        desyncAndroidReason,
			"disorder":        desyncAndroidReason,
		},
	}
	desyncCapsNone = desync.Capabilities{
		OS: "freebsd",
		Unsupported: map[string]string{
			"fake-tcp": "not implemented on this platform", "fake-udp": "not implemented on freebsd",
			"disorder": "not implemented on freebsd", "oob": "not implemented on freebsd",
			"auto-ttl-ipv4": "observing the server's TTL is not implemented on this platform",
			"auto-ttl-ipv6": "observing the server's TTL is not implemented on this platform",
		},
	}
)

const desyncAndroidReason = "Android does not let apps read SIOCOUTQNSD; unsent bytes are read from TCP_INFO tcpi_notsent_bytes (Linux 4.6+) when the socket provides it, so this is decided per socket: see ProbeCapabilities"

// A method the OS decides per socket (Conditional) is accepted, even though
// it is also listed as unsupported; the same caps without Conditional reject
// it, so the acceptance comes from Conditional alone.
func TestDesyncConditionalMethods(t *testing.T) {
	accepted := map[string]DesyncOption{
		"split-wait sent":       {Split: "1+s", SplitWait: "sent", SplitWaitTimeout: 500},
		"split-wait acked":      {Split: "1+s", SplitWait: "acked"},
		"disorder":              {Split: "1+s", Disorder: true},
		"disoob":                {Split: "1+s", Disorder: true, OOB: true},
		"fake":                  {TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4, SNI: []string{"www.example.com"}}},
		"fake auto-ttl":         {TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4, AutoTTL: &DesyncAutoTTLOption{}}},
		"fake disorder sent":    {Split: "1+s", Disorder: true, SplitWait: "sent", Fake: &DesyncFakeOption{TTL: 4}},
		"fake random split oob": {Random: &DesyncRandomOption{Split: []DesyncRandomCut{randomCut("1", "8", 1, 1)}}, OOB: true, Fake: &DesyncFakeOption{TTL: 4}},
		"udp":                   {UDP: &DesyncUDPOption{TTL: 4, Template: "quic"}},
	}
	for name, option := range accepted {
		option.Name = name
		d, err := newDesync(option, desyncCapsAndroid)
		if assert.NoError(t, err, name) {
			assert.Equal(t, option.SplitWait == "sent", d.tcp.SplitWait == desync.SplitWaitSent, name)
			assert.Equal(t, option.Disorder, d.tcp.Disorder, name)
			assert.Equal(t, option.Fake != nil, d.tcp.Fake != nil, name)
		}
	}

	strict := desyncCapsAndroid
	strict.Conditional = nil
	for _, tc := range []struct {
		name     string
		option   DesyncOption
		sentinel error
		message  string
	}{
		{"split-wait sent", DesyncOption{Split: "1+s", SplitWait: "sent"}, desync.ErrSplitWaitUnsupported, "split-wait sent is not supported on android (SIOCOUTQ observes only acked)"},
		{"disorder", DesyncOption{Split: "1+s", Disorder: true}, desync.ErrDisorderUnsupported, "disorder is not supported on android (Android does not let apps read SIOCOUTQNSD"},
		{"fake", DesyncOption{TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4}}, desync.ErrFakeUnsupported, "fake is not supported on android (Android does not let apps read SIOCOUTQNSD"},
	} {
		_, err := newDesync(tc.option, strict)
		if assert.Error(t, err, tc.name) {
			assert.ErrorIs(t, err, tc.sentinel, tc.name)
			assert.Contains(t, err.Error(), tc.message, tc.name)
		}
	}

	// Conditional does not lift the checks that do not depend on the socket.
	for _, tc := range []struct {
		name     string
		option   DesyncOption
		sentinel error
		message  string
	}{
		{"auto-ttl ipv4-only", DesyncOption{BasicOption: BasicOption{IPVersion: C.IPv4Only}, TLSRec: "1+s", Fake: &DesyncFakeOption{AutoTTL: &DesyncAutoTTLOption{}}}, desync.ErrAutoTTLUnsupported, "on android (Linux records no received TTL"},
		{"disorder without split", DesyncOption{TLSRec: "1+s", Disorder: true}, nil, "disorder needs split positions"},
		{"split-wait without split", DesyncOption{TLSRec: "1+s", SplitWait: "sent"}, nil, "split-wait needs split positions"},
	} {
		_, err := newDesync(tc.option, desyncCapsAndroid)
		if assert.Error(t, err, tc.name) {
			if tc.sentinel != nil {
				assert.ErrorIs(t, err, tc.sentinel, tc.name)
			}
			assert.Contains(t, err.Error(), tc.message, tc.name)
		}
	}
}

func TestDesyncUnsupportedPerOS(t *testing.T) {
	autoOnly := &DesyncFakeOption{AutoTTL: &DesyncAutoTTLOption{}}
	for _, tc := range []struct {
		name     string
		caps     desync.Capabilities
		option   DesyncOption
		sentinel error
		message  string
	}{
		{"darwin fake", desyncCapsDarwin, DesyncOption{TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4}}, desync.ErrFakeUnsupported, "fake is not supported on darwin (no splice"},
		{"darwin split-wait sent", desyncCapsDarwin, DesyncOption{Split: "1+s", SplitWait: "sent"}, desync.ErrSplitWaitUnsupported, "split-wait sent is not supported on darwin (SO_NWRITE observes only acked)"},
		{"windows auto-ttl without ttl", desyncCapsWindows, DesyncOption{TLSRec: "1+s", Fake: autoOnly}, desync.ErrAutoTTLUnsupported, "fake auto-ttl cannot observe the path on windows (Winsock"},
		{"linux auto-ttl ipv4-only", desyncCapsLinux, DesyncOption{BasicOption: BasicOption{IPVersion: C.IPv4Only}, TLSRec: "1+s", Fake: autoOnly}, desync.ErrAutoTTLUnsupported, "on linux (Linux records no received TTL"},
		{"none disorder", desyncCapsNone, DesyncOption{Split: "1+s", Disorder: true}, desync.ErrDisorderUnsupported, "disorder is not supported on freebsd (not implemented on freebsd)"},
		{"none oob", desyncCapsNone, DesyncOption{Split: "1+s", OOB: true}, desync.ErrOOBUnsupported, "oob is not supported on freebsd"},
		{"none split-wait", desyncCapsNone, DesyncOption{Split: "1+s", SplitWait: "acked"}, desync.ErrSplitWaitUnsupported, "split-wait acked is not supported on freebsd (the send queue cannot be observed)"},
		{"none fake", desyncCapsNone, DesyncOption{TLSRec: "1+s", Fake: &DesyncFakeOption{TTL: 4}}, desync.ErrFakeUnsupported, "fake is not supported on freebsd"},
		{"none udp", desyncCapsNone, DesyncOption{UDP: &DesyncUDPOption{TTL: 4, Template: "quic"}}, desync.ErrUDPFakeUnsupported, "udp is not supported on freebsd"},
	} {
		_, err := newDesync(tc.option, tc.caps)
		if assert.Error(t, err, tc.name) {
			assert.ErrorIs(t, err, tc.sentinel, tc.name)
			assert.Contains(t, err.Error(), tc.message, tc.name)
		}
	}
}

// withIPv6 lets the dialer use IPv6 addresses, which tests disable.
func withIPv6(t *testing.T) {
	t.Helper()
	old := resolver.DisableIPv6
	resolver.DisableIPv6 = false
	t.Cleanup(func() { resolver.DisableIPv6 = old })
}

// sendThrough writes input through a desync outbound to a loopback server
// and returns the bytes the server's socket read.
func sendThrough(t *testing.T, d *Desync, network string, input []byte) []byte {
	t.Helper()
	addr := "127.0.0.1:0"
	if network == "tcp6" {
		addr = "[::1]:0"
		withIPv6(t)
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("%s loopback: %v", network, err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 0, len(input)+256)
		tmp := make([]byte, 4096)
		for !bytes.HasSuffix(buf, []byte("after the hello")) {
			n, err := c.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if err != nil {
				break
			}
		}
		got <- buf
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, desyncMetadata(ln.Addr()))
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Write(input)
	require.NoError(t, err)
	require.Equal(t, len(input), n)
	return <-got
}

// Disorder, the out-of-band byte, split-wait and random write cuts change
// only how the ClientHello leaves the socket: through the outbound's own
// dial, the server reads the original stream byte for byte.
func TestDesyncSocketMethodsRoundTrip(t *testing.T) {
	caps := desync.PlatformCapabilities()
	randomSplit := &DesyncRandomOption{Split: []DesyncRandomCut{randomCut("1", "60", 3, 2), randomCut("-3+s", "3+s", 1, 1)}}
	cases := map[string]DesyncOption{
		"random split": {Random: randomSplit},
		"random seed":  {Split: "2", Random: &DesyncRandomOption{Split: randomSplit.Split, Seed: 42}, SplitDelay: 1},
	}
	if caps.Disorder.Supported {
		cases["disorder"] = DesyncOption{Split: "1+s", Disorder: true}
		cases["disorder random"] = DesyncOption{Random: randomSplit, Disorder: true, SplitWaitTimeout: 1000}
	}
	if caps.OOB {
		cases["oob"] = DesyncOption{Split: "1+s", OOB: true}
		cases["oob byte"] = DesyncOption{Split: "3,1+s", OOB: true, OOBByte: "#"}
	}
	if caps.Disorder.Supported && caps.OOB {
		cases["disoob"] = DesyncOption{Split: "1+s", Disorder: true, OOB: true}
	}
	if caps.Ack.Sent {
		cases["split-wait sent"] = DesyncOption{Split: "3,1+s", SplitWait: "sent", SplitWaitTimeout: 1000}
		if caps.Disorder.Supported {
			cases["disorder sent"] = DesyncOption{Split: "1+s", Disorder: true, SplitWait: "sent"}
		}
	}
	if caps.Ack.Acked {
		cases["split-wait acked"] = DesyncOption{Split: "3,1+s", SplitWait: "acked"}
		cases["split-wait acked random"] = DesyncOption{Random: randomSplit, SplitWait: "acked", SplitDelay: 1}
	}
	for name, option := range cases {
		for _, network := range []string{"tcp4", "tcp6"} {
			t.Run(name+"/"+network, func(t *testing.T) {
				input := append(captureClientHello(t), "after the hello"...)
				d := newTestDesync(t, option)
				assert.Equal(t, input, sendThrough(t, d, network, input))
			})
		}
	}
}

// Random record cuts add TLS records: the server reads the same handshake
// in more records, and a seed reproduces the cuts on every connection.
func TestDesyncRandomRecords(t *testing.T) {
	record := captureClientHello(t)
	input := append(append([]byte(nil), record...), "after the hello"...)
	option := DesyncOption{Random: &DesyncRandomOption{
		TLSRec: []DesyncRandomCut{randomCut("-6+s", "6+s", 2, 2), randomCut("10", "80", 3, 5)},
		Split:  []DesyncRandomCut{randomCut("1", "100", 2, 1)},
		Seed:   12345,
	}}
	d := newTestDesync(t, option)
	first := sendThrough(t, d, "tcp4", input)
	wire, joined, records, err := readHelloRecords(bytes.NewReader(first))
	require.NoError(t, err)
	assert.Equal(t, record, joined, "the handshake is unchanged")
	assert.GreaterOrEqual(t, records, 4, "random record cuts were added")
	assert.Equal(t, "after the hello", string(first[len(wire):]))
	assert.Equal(t, first, sendThrough(t, d, "tcp4", input), "the seed reproduces the cuts")

	option.Random.Seed = 0
	d = newTestDesync(t, option)
	_, joined, _, err = readHelloRecords(bytes.NewReader(sendThrough(t, d, "tcp4", input)))
	require.NoError(t, err)
	assert.Equal(t, record, joined)
}

func TestDesyncMarshalJSONMethods(t *testing.T) {
	caps := desync.PlatformCapabilities()
	if !caps.Disorder.Supported || !caps.OOB || !caps.Ack.Acked {
		t.Skip("disorder, oob and split-wait acked are not all implemented on this OS")
	}
	d := newTestDesync(t, DesyncOption{
		TLSRec: "1+s", Split: "2,1+s", SplitWait: "", Disorder: true, OOB: true, OOBByte: "z",
		Random: &DesyncRandomOption{
			TLSRec: []DesyncRandomCut{randomCut("-8+s", "8+s", 2, 2)},
			Split:  []DesyncRandomCut{randomCut("1", "120", 0, 0)},
			Seed:   99,
		},
	})
	raw, err := d.MarshalJSON()
	require.NoError(t, err)
	var v struct {
		Desync struct {
			TCP map[string]json.RawMessage `json:"tcp"`
		} `json:"desync"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	tcp := v.Desync.TCP
	assert.JSONEq(t, `"none"`, string(tcp["split-wait"]))
	assert.JSONEq(t, `2000`, string(tcp["split-wait-timeout"]), "the default bounds the disorder wait")
	assert.JSONEq(t, `true`, string(tcp["disorder"]))
	assert.JSONEq(t, `{"byte":"z"}`, string(tcp["oob"]))
	assert.JSONEq(t, `{"seed":99,
		"tlsrec":[{"from":"-8+s","to":"8+s","count":2,"min-piece":2}],
		"split":[{"from":"1","to":"120","count":1,"min-piece":1}]}`, string(tcp["random"]))
	assert.JSONEq(t, `null`, string(tcp["fake"]))

	d = newTestDesync(t, DesyncOption{Split: "1+s", SplitWait: "acked", SplitWaitTimeout: 700, OOB: true})
	raw, err = d.MarshalJSON()
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &v))
	assert.JSONEq(t, `"acked"`, string(v.Desync.TCP["split-wait"]))
	assert.JSONEq(t, `700`, string(v.Desync.TCP["split-wait-timeout"]))
	assert.JSONEq(t, `false`, string(v.Desync.TCP["disorder"]))
	assert.JSONEq(t, `{"byte":"a"}`, string(v.Desync.TCP["oob"]), "the library's default byte")
	assert.JSONEq(t, `null`, string(v.Desync.TCP["random"]))
}

func TestDesyncMarshalJSONFake(t *testing.T) {
	requireFake(t)
	d := newTestDesync(t, DesyncOption{
		Split: "1+s",
		Fake: &DesyncFakeOption{
			TTL: 6, AutoTTL: &DesyncAutoTTLOption{Delta: 2}, Prefix: -2,
			SNI: []string{"www.example.com"}, Randomize: true, FromOriginal: true, Offset: 3,
		},
	})
	raw, err := d.MarshalJSON()
	require.NoError(t, err)
	var v struct {
		Desync struct {
			TCP struct {
				Fake json.RawMessage `json:"fake"`
			} `json:"tcp"`
		} `json:"desync"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	assert.JSONEq(t, `{"ttl":6,"auto-ttl":{"delta":2,"min":3,"max":20},"prefix":-2,"timeout":3000,
		"sni":["www.example.com"],"randomize":true,"from-original":true,"offset":3,"last-ttl":null}`, string(v.Desync.TCP.Fake))
}

func TestDesyncMarshalJSONUDPQUIC(t *testing.T) {
	requireUDPFake(t)
	d := newTestDesync(t, DesyncOption{UDP: &DesyncUDPOption{TTL: 5, Template: "quic", QUICOnly: true}})
	raw, err := d.MarshalJSON()
	require.NoError(t, err)
	var v struct {
		Desync struct {
			UDP json.RawMessage `json:"udp"`
		} `json:"desync"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	assert.JSONEq(t, `{"ttl":5,"repeats":6,"packets":3,"template":"quic","sni":"`+desync.DefaultQUICSNI+`","quic-only":true,
		"counters":{"packets":0,"fakePackets":0,"fakeErrors":0,"peers":0}}`, string(v.Desync.UDP))
}

// A stream that does not start with a ClientHello is untouched by every
// method, and no fake is reported for it.
func TestDesyncMethodsPassThroughNonTLS(t *testing.T) {
	caps := desync.PlatformCapabilities()
	option := DesyncOption{Random: &DesyncRandomOption{Split: []DesyncRandomCut{randomCut("1", "20", 2, 1)}}}
	if caps.Disorder.Supported && caps.OOB {
		option.Disorder, option.OOB = true, true
	}
	if caps.FakeTCP {
		option.Fake = &DesyncFakeOption{TTL: 4, AutoTTL: &DesyncAutoTTLOption{}}
	}
	d := newTestDesync(t, option)
	input := []byte("GET / HTTP/1.1\r\nHost: www.youtube.test\r\n\r\nafter the hello")
	assert.Equal(t, input, sendThrough(t, d, "tcp4", input))
	raw, err := d.MarshalJSON()
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"last-ttl":{`, "no fake was sent")
}
