package inbound_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSSKey(size int) string {
	b := make([]byte, size)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// inUserRecorder wraps a TestTunnel and records metadata.InUser of every
// TCP connection and UDP packet the inbound hands to the tunnel.
type inUserRecorder struct {
	mu    sync.Mutex
	users map[string]int
}

func (r *inUserRecorder) record(user string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users[user]++
}

func (r *inUserRecorder) take() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	users := r.users
	r.users = map[string]int{}
	return users
}

func TestInboundShadowSocks_MultiUser(t *testing.T) {
	for _, cipher := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-aes-256-ccm"} {
		cipher := cipher
		t.Run(cipher, func(t *testing.T) {
			t.Parallel()
			keySize := 32
			if cipher == "2022-blake3-aes-128-gcm" {
				keySize = 16
			}
			testInboundShadowSocksMultiUser(t, cipher, keySize)
		})
	}
}

func testInboundShadowSocksMultiUser(t *testing.T, cipher string, keySize int) {
	iPSK := newSSKey(keySize)
	users := []inbound.ShadowSocksUser{
		{Name: "alice", Password: newSSKey(keySize)},
		{Name: "bob", Password: newSSKey(keySize)},
	}
	in, err := inbound.NewShadowSocks(&inbound.ShadowSocksOption{
		BaseOption: inbound.BaseOption{NameStr: "shadowsocks_inbound", Listen: "127.0.0.1", Port: "0"},
		Password:   iPSK,
		Cipher:     cipher,
		Users:      users,
		UDP:        true,
	})
	require.NoError(t, err)

	rec := &inUserRecorder{users: map[string]int{}}
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	handleTCP := tunnel.HandleTCPConnFn
	tunnel.HandleTCPConnFn = func(conn net.Conn, metadata *C.Metadata) {
		rec.record(metadata.InUser)
		handleTCP(conn, metadata)
	}
	tunnel.HandleUDPPacketFn = func(packet C.UDPPacket, metadata *C.Metadata) {
		rec.record(metadata.InUser)
		_, _ = packet.WriteBack(packet.Data(), metadata.UDPAddr()) // echo from the destination
		packet.Drop()
	}

	require.NoError(t, in.Listen(tunnel))
	defer in.Close()

	// Port 0 binds TCP and UDP to different ports; AddrList lists TCP first.
	addrs := splitAddrs(in.Address())
	require.Len(t, addrs, 2, in.Address())
	tcpAddr, udpAddr := netip.MustParseAddrPort(addrs[0]), netip.MustParseAddrPort(addrs[1])

	newOut := func(password string, addr netip.AddrPort) *outbound.ShadowSocks {
		option := outbound.ShadowSocksOption{
			Name:     "shadowsocks_outbound",
			Server:   addr.Addr().String(),
			Port:     int(addr.Port()),
			Password: password,
			Cipher:   cipher,
			UDP:      true,
		}
		option.DialerForAPI = tunnel.NewDialer()
		option.TunnelForAPI = tunnel
		out, err := outbound.NewShadowSocks(option)
		require.NoError(t, err)
		return out
	}

	for _, user := range users {
		t.Run(user.Name, func(t *testing.T) {
			out := newOut(iPSK+":"+user.Password, tcpAddr)
			defer out.Close()
			rec.take()
			tunnel.DoSequentialTest(t, out)
			assert.Equal(t, []string{user.Name}, keys(rec.take()), "TCP InUser")

			udpOut := newOut(iPSK+":"+user.Password, udpAddr)
			defer udpOut.Close()
			assert.NoError(t, udpEcho(udpOut, 5*time.Second), "UDP")
			assert.Equal(t, []string{user.Name}, keys(rec.take()), "UDP InUser")
		})
	}

	for name, password := range map[string]string{
		"wrong uPSK": iPSK + ":" + newSSKey(keySize),
		"no uPSK":    iPSK,
	} {
		t.Run(name, func(t *testing.T) {
			out := newOut(password, tcpAddr)
			defer out.Close()
			rec.take()
			assert.Error(t, tcpRoundTrip(out), "TCP must be rejected")

			udpOut := newOut(password, udpAddr)
			defer udpOut.Close()
			assert.Error(t, udpEcho(udpOut, time.Second), "UDP must be dropped")
			assert.Empty(t, rec.take(), "nothing must reach the tunnel")
		})
	}
}

func tcpRoundTrip(out *outbound.ShadowSocks) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: remoteAddr, DstPort: 80})
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		return err
	}
	_, err = conn.Read(make([]byte, 16))
	return err
}

func udpEcho(out *outbound.ShadowSocks, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	metadata := &C.Metadata{NetWork: C.UDP, DstIP: remoteAddr, DstPort: 53}
	pc, err := out.ListenPacketContext(ctx, metadata)
	if err != nil {
		return err
	}
	defer pc.Close()
	payload := []byte("citrus-ss2022-eih")
	dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(remoteAddr, 53))
	_ = pc.SetDeadline(time.Now().Add(timeout))
	if _, err = pc.WriteTo(payload, dst); err != nil {
		return err
	}
	buf := make([]byte, 1024)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != string(payload) {
		return assert.AnError
	}
	return nil
}

func splitAddrs(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func keys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestInboundShadowSocks_MultiUserValidation(t *testing.T) {
	k16, k32 := newSSKey(16), newSSKey(32)
	cases := []struct {
		name     string
		cipher   string
		password string
		users    []inbound.ShadowSocksUser
		err      string
	}{
		{"non-2022 method", "aes-256-gcm", "pw", []inbound.ShadowSocksUser{{Name: "a", Password: k32}}, "only supported with 2022-blake3-aes"},
		{"chacha20 2022 has no EIH", "2022-blake3-chacha20-poly1305", k32, []inbound.ShadowSocksUser{{Name: "a", Password: k32}}, "only supported with 2022-blake3-aes"},
		{"bad iPSK length", "2022-blake3-aes-256-gcm", k16, []inbound.ShadowSocksUser{{Name: "a", Password: k32}}, "iPSK"},
		{"bad uPSK length", "2022-blake3-aes-128-gcm", k16, []inbound.ShadowSocksUser{{Name: "a", Password: k32}}, "uPSK"},
		{"bad uPSK base64", "2022-blake3-aes-128-gcm", k16, []inbound.ShadowSocksUser{{Name: "a", Password: "not base64!"}}, "uPSK"},
		{"empty name", "2022-blake3-aes-128-gcm", k16, []inbound.ShadowSocksUser{{Password: newSSKey(16)}}, "empty name"},
		{"duplicate name", "2022-blake3-aes-128-gcm", k16, []inbound.ShadowSocksUser{{Name: "a", Password: newSSKey(16)}, {Name: "a", Password: newSSKey(16)}}, "duplicate user name"},
		{"shared uPSK", "2022-blake3-aes-128-gcm", k16, func() []inbound.ShadowSocksUser {
			k := newSSKey(16)
			return []inbound.ShadowSocksUser{{Name: "a", Password: k}, {Name: "b", Password: k}}
		}(), "share a password"},
		{"uPSK equals iPSK", "2022-blake3-aes-128-gcm", k16, []inbound.ShadowSocksUser{{Name: "a", Password: k16}}, "equals the server password"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := inbound.NewShadowSocks(&inbound.ShadowSocksOption{
				BaseOption: inbound.BaseOption{NameStr: "shadowsocks_inbound", Listen: "127.0.0.1", Port: "0"},
				Password:   tc.password,
				Cipher:     tc.cipher,
				Users:      tc.users,
			})
			assert.ErrorContains(t, err, tc.err)
		})
	}
}
