package inbound_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/assert"
)

func newRealityMldsa65Keys(t *testing.T) (seed, verify string) {
	t.Helper()
	seedBytes := make([]byte, utls.RealityMldsa65SeedSize)
	_, _ = rand.Read(seedBytes)
	verifyBytes, err := utls.RealityMldsa65Verify(seedBytes)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(seedBytes), base64.RawURLEncoding.EncodeToString(verifyBytes)
}

func realityPQOptions(t *testing.T) (inbound.VlessOption, outbound.VlessOption) {
	seed, verify := newRealityMldsa65Keys(t)
	inboundOptions := inbound.VlessOption{
		RealityConfig: inbound.RealityConfig{
			Dest:                  net.JoinHostPort(realityDest, "443"),
			PrivateKey:            realityPrivateKey,
			ShortID:               []string{realityShortid},
			ServerNames:           []string{realityDest},
			Mldsa65Seed:           seed,
			RequireX25519MLKEM768: true,
			MinClientVer:          "25.0.0",
		},
	}
	outboundOptions := outbound.VlessOption{
		TLS:        true,
		ServerName: realityDest,
		RealityOpts: outbound.RealityOptions{
			PublicKey:     realityPublickey,
			ShortID:       realityShortid,
			Mldsa65Verify: verify,
		},
		ClientFingerprint: "chrome",
	}
	return inboundOptions, outboundOptions
}

// testInboundVlessRealityRejected checks that the REALITY server does not accept the client.
func testInboundVlessRealityRejected(t *testing.T, inboundOptions inbound.VlessOption, outboundOptions outbound.VlessOption) {
	t.Parallel()
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "vless_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Users = []inbound.VlessUser{{Username: "test", UUID: userUUID}}
	in, err := inbound.NewVless(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	if !assert.NoError(t, in.Listen(tunnel)) {
		return
	}
	defer in.Close()
	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}

	outboundOptions.Name = "vless_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.UUID = userUUID
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel
	out, err := outbound.NewVless(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: remoteAddr, DstPort: 80})
	if err == nil {
		conn.Close()
		t.Error("REALITY client is accepted")
	}
}

func TestInboundVless_RealityPQ(t *testing.T) {
	inboundOptions, outboundOptions := realityPQOptions(t)
	testInboundVless(t, inboundOptions, outboundOptions)
	t.Run("xtls-rprx-vision", func(t *testing.T) {
		outboundOptions := outboundOptions
		outboundOptions.Flow = "xtls-rprx-vision"
		testInboundVless(t, inboundOptions, outboundOptions)
	})
	t.Run("WithoutMldsa65Verify", func(t *testing.T) {
		outboundOptions := outboundOptions
		outboundOptions.RealityOpts.Mldsa65Verify = ""
		testInboundVless(t, inboundOptions, outboundOptions)
	})
	// the real post-quantum parrots, and the classical ones with an injected X25519MLKEM768 key share
	for _, fingerprint := range []string{"firefox", "safari", "ios", "edge", "qq", "random", "randomized",
		"chrome120", "firefox120", "safari16", "hellofirefox_148", "hellosafari_26_3", "hellochrome_131", "helloios_13"} {
		t.Run(fingerprint, func(t *testing.T) {
			outboundOptions := outboundOptions
			outboundOptions.ClientFingerprint = fingerprint
			testInboundVless(t, inboundOptions, outboundOptions)
		})
	}
	t.Run("WrongMldsa65Verify", func(t *testing.T) {
		outboundOptions := outboundOptions
		_, outboundOptions.RealityOpts.Mldsa65Verify = newRealityMldsa65Keys(t)
		testInboundVlessRealityRejected(t, inboundOptions, outboundOptions)
	})
	t.Run("DisableX25519MLKEM768", func(t *testing.T) {
		outboundOptions := outboundOptions
		supportX25519MLKEM768 := false
		outboundOptions.RealityOpts.SupportX25519MLKEM768 = &supportX25519MLKEM768
		testInboundVlessRealityRejected(t, inboundOptions, outboundOptions)
	})
	t.Run("MinClientVer", func(t *testing.T) {
		outboundOptions := outboundOptions
		outboundOptions.RealityOpts.ClientVersion = "24.12.31"
		testInboundVlessRealityRejected(t, inboundOptions, outboundOptions)
	})
	t.Run("MaxClientVer", func(t *testing.T) {
		inboundOptions := inboundOptions
		inboundOptions.RealityConfig.MaxClientVer = "26.9.8"
		testInboundVlessRealityRejected(t, inboundOptions, outboundOptions) // the default client version is 26.10.10
		outboundOptions := outboundOptions
		outboundOptions.RealityOpts.ClientVersion = "26.9.8"
		t.Run("Accepted", func(t *testing.T) {
			testInboundVless(t, inboundOptions, outboundOptions)
		})
	})
}

func TestInboundVless_RealityInvalidOptions(t *testing.T) {
	for name, modify := range map[string]func(*inbound.RealityConfig){
		"mldsa65-seed":   func(c *inbound.RealityConfig) { c.Mldsa65Seed = "too-short" },
		"min-client-ver": func(c *inbound.RealityConfig) { c.MinClientVer = "26.300.1" },
		"max-client-ver": func(c *inbound.RealityConfig) { c.MaxClientVer = "1.2.3.4" },
	} {
		t.Run(name, func(t *testing.T) {
			inboundOptions, _ := realityPQOptions(t)
			modify(&inboundOptions.RealityConfig)
			inboundOptions.BaseOption = inbound.BaseOption{NameStr: "vless_inbound", Listen: "127.0.0.1", Port: "0"}
			inboundOptions.Users = []inbound.VlessUser{{Username: "test", UUID: userUUID}}
			in, err := inbound.NewVless(&inboundOptions)
			if err != nil {
				return // rejected when parsing
			}
			tunnel := NewHttpTestTunnel()
			defer tunnel.Close()
			if err = in.Listen(tunnel); err == nil {
				in.Close()
				t.Error("invalid option accepted")
			}
		})
	}
}

func TestInboundTrojan_RealityPQ(t *testing.T) {
	vlessInbound, vlessOutbound := realityPQOptions(t)
	inboundOptions := inbound.TrojanOption{RealityConfig: vlessInbound.RealityConfig}
	outboundOptions := outbound.TrojanOption{
		SNI:               realityDest,
		RealityOpts:       vlessOutbound.RealityOpts,
		ClientFingerprint: "firefox",
	}
	testInboundTrojan(t, inboundOptions, outboundOptions)
}
