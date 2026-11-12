package inbound_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/require"
)

// freeUDPRange finds n consecutive free UDP ports on 127.0.0.1.
func freeUDPRange(t *testing.T, n int) int {
	t.Helper()
	for range 50 {
		first := 20000 + rand.IntN(40000-n)
		var held []net.PacketConn
		for p := first; p < first+n; p++ {
			c, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", p))
			if err != nil {
				break
			}
			held = append(held, c)
		}
		for _, c := range held {
			_ = c.Close()
		}
		if len(held) == n {
			return first
		}
	}
	t.Fatal("no free range of UDP ports")
	return 0
}

// TestInboundHysteria2_PortHopping keeps one connection busy while the client
// hops between the ports of the range: the QUIC connection must survive every
// hop, which needs one QUIC server for the whole range.
func TestInboundHysteria2_PortHopping(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the client to hop")
	}
	t.Parallel()
	for _, obfs := range []string{"", "salamander", "gecko"} {
		name := obfs
		if name == "" {
			name = "plain"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			testInboundHysteria2PortHopping(t, obfs)
		})
	}
}

func testInboundHysteria2PortHopping(t *testing.T, obfs string) {
	const ports = 10
	first := freeUDPRange(t, ports)
	spec := fmt.Sprintf("%d-%d", first, first+ports-1)

	in, err := inbound.NewHysteria2(&inbound.Hysteria2Option{
		BaseOption:   inbound.BaseOption{NameStr: "hysteria2_hop", Listen: "127.0.0.1", Port: spec},
		Users:        map[string]string{"test": userUUID},
		Certificate:  tlsCertificate,
		PrivateKey:   tlsPrivateKey,
		Obfs:         obfs,
		ObfsPassword: userUUID,
	})
	require.NoError(t, err)
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	require.NoError(t, in.Listen(tunnel))
	defer in.Close()

	outboundOptions := outbound.Hysteria2Option{
		Name:         "hysteria2_hop_out",
		Server:       "127.0.0.1",
		Ports:        spec,
		HopInterval:  "5",
		Password:     userUUID,
		Fingerprint:  tlsFingerprint,
		Obfs:         obfs,
		ObfsPassword: userUUID,
	}
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel
	out, err := outbound.NewHysteria2(outboundOptions)
	require.NoError(t, err)
	defer out.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	conn, err := out.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: remoteAddr, DstPort: 80})
	require.NoError(t, err)
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// the client hops every 5 seconds: three hops, each to a random port of
	// the ten (so a hop to another port is all but certain)
	const size = 1024
	start := time.Now()
	for i := 0; time.Since(start) < 17*time.Second; i++ {
		require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
		req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s%s?size=%d", remoteAddr, httpPath, size), bytes.NewReader(httpData[:16]))
		require.NoError(t, err)
		require.NoError(t, req.Write(conn), "request %d at %s", i, time.Since(start).Round(time.Second))
		resp, err := http.ReadResponse(reader, req)
		require.NoError(t, err, "response %d at %s", i, time.Since(start).Round(time.Second))
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err, "body %d at %s", i, time.Since(start).Round(time.Second))
		require.Equal(t, httpData[:size], body)
		time.Sleep(time.Second)
	}
}
