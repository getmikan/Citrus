package inbound_test

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/proxyproto"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/trojan"
	"github.com/metacubex/mihomo/transport/vless/encryption"

	"github.com/gofrs/uuid/v5"
)

// fallbackHit is what a fallback backend got: the PROXY header (if it reads
// one) and the bytes up to the end of the first request.
type fallbackHit struct {
	header proxyproto.Header
	data   []byte
}

// fallbackBackend is a TCP server a fallback points to: it answers every
// connection with an HTTP/1.1 response whose body is its tag, after reading
// a PROXY header when xver.
type fallbackBackend struct {
	addr string
	hits chan fallbackHit
}

func startFallbackBackend(t *testing.T, tag string, xver bool) *fallbackBackend {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	b := &fallbackBackend{addr: l.Addr().String(), hits: make(chan fallbackHit, 16)}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var hit fallbackHit
				if xver {
					if hit.header, err = proxyproto.Read(c); err != nil {
						return
					}
				}
				buf := make([]byte, 4096)
				for !bytes.Contains(hit.data, []byte("\r\n\r\n")) {
					n, err := c.Read(buf)
					hit.data = append(hit.data, buf[:n]...)
					if err != nil {
						break
					}
				}
				b.hits <- hit
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: "+strconv.Itoa(len(tag))+"\r\nConnection: close\r\n\r\n"+tag)
			}()
		}
	}()
	return b
}

func (b *fallbackBackend) hit(t *testing.T) fallbackHit {
	t.Helper()
	select {
	case hit := <-b.hits:
		return hit
	case <-time.After(5 * time.Second):
		t.Fatal("the fallback got no connection")
		return fallbackHit{}
	}
}

// fallbackDial connects to addr over TLS with sni and alpn, writes payload and
// returns all it reads back, and the conn's local address.
func fallbackDial(t *testing.T, addr, sni, alpn string, payload []byte) (string, net.Addr) {
	t.Helper()
	config := &tls.Config{ServerName: sni, InsecureSkipVerify: true}
	if alpn != "" {
		config.NextProtos = []string{alpn}
	}
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, config)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.ConnectionState().NegotiatedProtocol; got != alpn {
		t.Fatalf("negotiated ALPN %q, want %q", got, alpn)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	resp, _ := io.ReadAll(c)
	return string(resp), c.LocalAddr()
}

func httpGet(path string) []byte {
	return []byte("GET " + path + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
}

// fallbackBackends are the targets of the fallbacks of the tests: one per
// way to match.
type fallbackBackends struct {
	any, path, h2, sni, wildcard, v1, v2 *fallbackBackend
}

func startFallbackBackends(t *testing.T) (fallbackBackends, []inbound.Fallback) {
	b := fallbackBackends{
		any:      startFallbackBackend(t, "any", false),
		path:     startFallbackBackend(t, "path", false),
		h2:       startFallbackBackend(t, "h2", false),
		sni:      startFallbackBackend(t, "sni", false),
		wildcard: startFallbackBackend(t, "wildcard", false),
		v1:       startFallbackBackend(t, "v1", true),
		v2:       startFallbackBackend(t, "v2", true),
	}
	_, port, _ := net.SplitHostPort(b.any.addr)
	return b, []inbound.Fallback{
		{Dest: port}, // a bare port is on 127.0.0.1
		{Path: "/app", Dest: b.path.addr},
		{ALPN: "h2", Dest: b.h2.addr},
		{Name: "a.example.com", Dest: b.sni.addr},
		{Name: "*.example.com", Dest: b.wildcard.addr},
		{Path: "/v1", Dest: b.v1.addr, Xver: 1},
		{Path: "/v2", Dest: b.v2.addr, Xver: 2},
	}
}

// checkFallbackRouting sends streams that are not the inbound's own to addr
// and checks which backend each reaches, with the bytes read before it was
// chosen replayed and the PROXY header of xver.
func checkFallbackRouting(t *testing.T, addr string, b fallbackBackends) {
	server := netip.MustParseAddrPort(addr)
	for _, tt := range []struct {
		name, sni, alpn string
		payload         []byte
		want            *fallbackBackend
		tag             string
	}{
		{name: "any", payload: httpGet("/"), want: b.any, tag: "any"},
		{name: "query is not the path", payload: httpGet("/app?x=1"), want: b.path, tag: "path"},
		{name: "path", payload: httpGet("/app"), want: b.path, tag: "path"},
		{name: "other path", payload: httpGet("/app2"), want: b.any, tag: "any"},
		{name: "alpn", alpn: "h2", payload: []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), want: b.h2, tag: "h2"},
		{name: "alpn http/1.1 is offered", alpn: "http/1.1", payload: httpGet("/"), want: b.any, tag: "any"},
		{name: "sni before path", sni: "a.example.com", payload: httpGet("/app"), want: b.sni, tag: "sni"},
		{name: "wildcard sni", sni: "b.example.com", payload: httpGet("/"), want: b.wildcard, tag: "wildcard"},
		{name: "wildcard does not take the apex", sni: "example.com", payload: httpGet("/"), want: b.any, tag: "any"},
		{name: "one byte", payload: []byte("x\r\n\r\n"), want: b.any, tag: "any"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp, _ := fallbackDial(t, addr, tt.sni, tt.alpn, tt.payload)
			if !strings.HasSuffix(resp, "\r\n\r\n"+tt.tag) {
				t.Fatalf("response %q, want the body %q", resp, tt.tag)
			}
			if hit := tt.want.hit(t); !bytes.Equal(hit.data, tt.payload) {
				t.Fatalf("the fallback got %q, want %q", hit.data, tt.payload)
			}
		})
	}
	for _, tt := range []struct {
		path    string
		backend *fallbackBackend
		version int
	}{{"/v1", b.v1, 1}, {"/v2", b.v2, 2}} {
		t.Run("xver "+strconv.Itoa(tt.version), func(t *testing.T) {
			payload := httpGet(tt.path)
			_, local := fallbackDial(t, addr, "", "", payload)
			hit := tt.backend.hit(t)
			want := proxyproto.Header{
				Version:     tt.version,
				Source:      local.(*net.TCPAddr).AddrPort(),
				Destination: server,
			}
			if hit.header != want {
				t.Fatalf("PROXY header %+v, want %+v", hit.header, want)
			}
			if !bytes.Equal(hit.data, payload) {
				t.Fatalf("the fallback got %q after the header, want %q", hit.data, payload)
			}
		})
	}
}

// TestInboundVlessFallbacks: on the plain TCP transport a stream that is not
// VLESS, or VLESS with an unknown UUID, goes to the fallback that matches its
// SNI, ALPN and path best, with what was read of it and the PROXY header of
// xver; with none that matches it is closed.
func TestInboundVlessFallbacks(t *testing.T) {
	backends, fallbacks := startFallbackBackends(t)
	addr := listenVless(t, inbound.VlessOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
		Fallbacks:   fallbacks,
	})
	checkFallbackRouting(t, addr, backends)

	t.Run("unknown uuid", func(t *testing.T) {
		header := append([]byte{0}, uuid.Must(uuid.NewV4()).Bytes()...)
		header = append(header, 0, 1, 0, 80, 1, 1, 2, 3, 4, '\r', '\n', '\r', '\n')
		resp, _ := fallbackDial(t, addr, "", "", header)
		if !strings.HasSuffix(resp, "any") {
			t.Fatalf("response %q", resp)
		}
		if hit := backends.any.hit(t); !bytes.Equal(hit.data, header) {
			t.Fatalf("the fallback got %x, want %x", hit.data, header)
		}
	})

	t.Run("no match closes", func(t *testing.T) {
		only := startFallbackBackend(t, "only", false)
		addr := listenVless(t, inbound.VlessOption{
			Certificate: tlsCertificate,
			PrivateKey:  tlsPrivateKey,
			Fallbacks:   []inbound.Fallback{{Name: "a.example.com", Dest: only.addr}},
		})
		if resp, _ := fallbackDial(t, addr, "b.example.com", "", httpGet("/")); resp != "" {
			t.Fatalf("response %q, want the conn closed", resp)
		}
		select {
		case <-only.hits:
			t.Fatal("a stream that matches no fallback reached one")
		default:
		}
	})
}

// TestInboundVlessFallbacks_Client: a real VLESS client, vision included,
// still works on a listener with fallbacks (and the ALPNs they offer).
func TestInboundVlessFallbacks_Client(t *testing.T) {
	_, fallbacks := startFallbackBackends(t)
	inboundOptions := inbound.VlessOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
		Fallbacks:   fallbacks,
	}
	outboundOptions := outbound.VlessOption{
		TLS:         true,
		Fingerprint: tlsFingerprint,
	}
	testInboundVlessTLS(t, inboundOptions, outboundOptions, true)
}

// listenTrojan starts a Trojan inbound on loopback and returns its address.
func listenTrojan(t *testing.T, opt inbound.TrojanOption) string {
	t.Helper()
	opt.BaseOption = inbound.BaseOption{NameStr: "trojan_fallback", Listen: "127.0.0.1", Port: "0"}
	opt.Users = []inbound.TrojanUser{{Username: "test", Password: userUUID}}
	in, err := inbound.NewTrojan(&opt)
	if err != nil {
		t.Fatal(err)
	}
	tunnel := NewHttpTestTunnel()
	t.Cleanup(func() { tunnel.Close() })
	if err := in.Listen(tunnel); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close() })
	return in.Address()
}

// TestInboundTrojanFallbacks: as TestInboundVlessFallbacks, for a stream that
// is not Trojan or has the key of no user.
func TestInboundTrojanFallbacks(t *testing.T) {
	backends, fallbacks := startFallbackBackends(t)
	addr := listenTrojan(t, inbound.TrojanOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
		Fallbacks:   fallbacks,
	})
	checkFallbackRouting(t, addr, backends)

	t.Run("unknown key", func(t *testing.T) {
		key := trojan.Key("wrong")
		header := append(key[:], "\r\n\x01\x01\x01\x02\x03\x04\x00\x50\r\n\r\n"...)
		resp, _ := fallbackDial(t, addr, "", "", header)
		if !strings.HasSuffix(resp, "any") {
			t.Fatalf("response %q", resp)
		}
		if hit := backends.any.hit(t); !bytes.Equal(hit.data, header) {
			t.Fatalf("the fallback got %q, want %q", hit.data, header)
		}
	})

	t.Run("hex that is no key", func(t *testing.T) {
		payload := []byte(hex.EncodeToString([]byte("short")) + "\r\n\r\n")
		resp, _ := fallbackDial(t, addr, "", "", payload)
		if !strings.HasSuffix(resp, "any") {
			t.Fatalf("response %q", resp)
		}
		if hit := backends.any.hit(t); !bytes.Equal(hit.data, payload) {
			t.Fatalf("the fallback got %q, want %q", hit.data, payload)
		}
	})
}

// TestInboundTrojanFallbacks_Client: a real Trojan client still works on a
// listener with fallbacks.
func TestInboundTrojanFallbacks_Client(t *testing.T) {
	_, fallbacks := startFallbackBackends(t)
	inboundOptions := inbound.TrojanOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
		Fallbacks:   fallbacks,
	}
	outboundOptions := outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
	}
	testInboundTrojanTLS(t, inboundOptions, outboundOptions)
}

// TestInboundFallbacksConfig: fallbacks the listener cannot serve start no
// listener.
func TestInboundFallbacksConfig(t *testing.T) {
	ok := []inbound.Fallback{{Dest: "8080"}}
	privateKey, _, _, err := encryption.GenX25519("")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name  string
		vless *inbound.VlessOption
		troj  *inbound.TrojanOption
	}{
		{name: "vless ws", vless: &inbound.VlessOption{WsPath: "/ws", Fallbacks: ok}},
		{name: "vless grpc", vless: &inbound.VlessOption{GrpcServiceName: "svc", Fallbacks: ok}},
		{name: "vless xhttp", vless: &inbound.VlessOption{XHTTPConfig: inbound.XHTTPConfig{Path: "/x"}, Fallbacks: ok}},
		{name: "vless decryption", vless: &inbound.VlessOption{Decryption: "mlkem768x25519plus.native.600s." + privateKey, Fallbacks: ok}},
		{name: "no dest", vless: &inbound.VlessOption{Fallbacks: []inbound.Fallback{{Path: "/x"}}}},
		{name: "bad dest", vless: &inbound.VlessOption{Fallbacks: []inbound.Fallback{{Dest: "localhost"}}}},
		{name: "bad xver", vless: &inbound.VlessOption{Fallbacks: []inbound.Fallback{{Dest: "80", Xver: 3}}}},
		{name: "relative path", vless: &inbound.VlessOption{Fallbacks: []inbound.Fallback{{Dest: "80", Path: "x"}}}},
		{name: "bad wildcard", vless: &inbound.VlessOption{Fallbacks: []inbound.Fallback{{Dest: "80", Name: "a.*.com"}}}},
		{name: "duplicate", vless: &inbound.VlessOption{Fallbacks: []inbound.Fallback{{Dest: "80"}, {Dest: "81"}}}},
		{name: "trojan ws", troj: &inbound.TrojanOption{WsPath: "/ws", Fallbacks: ok}},
		{name: "trojan ss", troj: &inbound.TrojanOption{SSOption: inbound.TrojanSSOption{Enabled: true, Password: "x"}, Fallbacks: ok}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tunnel := NewHttpTestTunnel()
			defer tunnel.Close()
			var err error
			if tt.vless != nil {
				opt := *tt.vless
				opt.BaseOption = inbound.BaseOption{NameStr: "vless_fallbacks", Listen: "127.0.0.1", Port: "0"}
				opt.Users = []inbound.VlessUser{{Username: "test", UUID: userUUID}}
				opt.Certificate, opt.PrivateKey = tlsCertificate, tlsPrivateKey
				var in *inbound.Vless
				if in, err = inbound.NewVless(&opt); err == nil {
					if err = in.Listen(tunnel); err == nil {
						in.Close()
					}
				}
			} else {
				opt := *tt.troj
				opt.BaseOption = inbound.BaseOption{NameStr: "trojan_fallbacks", Listen: "127.0.0.1", Port: "0"}
				opt.Users = []inbound.TrojanUser{{Username: "test", Password: userUUID}}
				opt.Certificate, opt.PrivateKey = tlsCertificate, tlsPrivateKey
				var in *inbound.Trojan
				if in, err = inbound.NewTrojan(&opt); err == nil {
					if err = in.Listen(tunnel); err == nil {
						in.Close()
					}
				}
			}
			if err == nil || !strings.Contains(err.Error(), "fallbacks") {
				t.Fatalf("error %v, want one about the fallbacks", err)
			}
		})
	}
}
