package inbound_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startEchoServer echoes every connection back. It resets the connections
// it closes (see abortiveDialer): the DIRECT side, which closes first, then
// leaves no TIME_WAIT behind either.
func startEchoServer(t *testing.T) netip.AddrPort {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

// echoSession opens a connection to the echo server through out and checks
// one round trip.
func echoSession(out C.ProxyAdapter, echo netip.AddrPort) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: echo.Addr(), DstPort: echo.Port()})
	if err != nil {
		return nil, err
	}
	if err = ping(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// ping sends a few bytes over an echo connection and reads them back.
func ping(conn net.Conn) error {
	payload := make([]byte, 16)
	_, _ = rand.Read(payload)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetDeadline(time.Time{})
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("echo mismatch")
	}
	return nil
}

// abortiveDialer dials the TCP connections of the test clients with
// SO_LINGER 0: closing one resets it instead of leaving it in TIME_WAIT. A
// run of TestInboundRuntimeUsersConcurrent opens about two thousand loopback
// connections (the clients' and DIRECT's), and with -count=N their TIME_WAITs
// use up the ephemeral ports: on Windows the dials then fail with
// WSAEADDRINUSE, which the test would count as refused sessions.
type abortiveDialer struct{}

func (abortiveDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	return c, nil
}

func (abortiveDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	return dialer.NewDialer().ListenPacket(ctx, network, address, rAddrPort)
}

var testBasic = outbound.BasicOption{DialerForAPI: abortiveDialer{}}

// runtimeUsersProto builds an inbound of one protocol and clients for it.
type runtimeUsersProto struct {
	name    string
	newUser func(name string) C.InboundUser
	newIn   func(t *testing.T, name string, users []C.InboundUser) C.InboundListener
	newOut  func(t *testing.T, addr netip.AddrPort, user C.InboundUser) C.ProxyAdapter
}

var runtimeUsersIPSK = newSSKey(16)

func runtimeUsersProtos() []runtimeUsersProto {
	uuidUser := func(name string) C.InboundUser {
		return C.InboundUser{Name: name, Secret: utils.NewUUIDV4().String()}
	}
	base := func(name string) inbound.BaseOption {
		return inbound.BaseOption{NameStr: name, Listen: "127.0.0.1", Port: "0"}
	}
	authUsers := func(users []C.InboundUser) inbound.AuthUsers {
		a := make(inbound.AuthUsers, len(users))
		for i, u := range users {
			a[i] = inbound.AuthUser{Username: u.Name, Password: u.Secret}
		}
		return a
	}
	mapUsers := func(users []C.InboundUser) map[string]string {
		m := make(map[string]string, len(users))
		for _, u := range users {
			m[u.Name] = u.Secret
		}
		return m
	}
	return []runtimeUsersProto{
		{
			name:    "vless",
			newUser: uuidUser,
			newIn: func(t *testing.T, name string, users []C.InboundUser) C.InboundListener {
				vu := make([]inbound.VlessUser, len(users))
				for i, u := range users {
					vu[i] = inbound.VlessUser{Username: u.Name, UUID: u.Secret, Flow: u.Flow}
				}
				in, err := inbound.NewVless(&inbound.VlessOption{BaseOption: base(name), Users: vu, AllowInsecure: true})
				require.NoError(t, err)
				return in
			},
			newOut: func(t *testing.T, addr netip.AddrPort, user C.InboundUser) C.ProxyAdapter {
				out, err := outbound.NewVless(outbound.VlessOption{BasicOption: testBasic, Name: "out", Server: addr.Addr().String(), Port: int(addr.Port()), UUID: user.Secret})
				require.NoError(t, err)
				return out
			},
		},
		{
			name:    "trojan",
			newUser: uuidUser,
			newIn: func(t *testing.T, name string, users []C.InboundUser) C.InboundListener {
				tu := make([]inbound.TrojanUser, len(users))
				for i, u := range users {
					tu[i] = inbound.TrojanUser{Username: u.Name, Password: u.Secret}
				}
				in, err := inbound.NewTrojan(&inbound.TrojanOption{BaseOption: base(name), Users: tu, Certificate: tlsCertificate, PrivateKey: tlsPrivateKey})
				require.NoError(t, err)
				return in
			},
			newOut: func(t *testing.T, addr netip.AddrPort, user C.InboundUser) C.ProxyAdapter {
				out, err := outbound.NewTrojan(outbound.TrojanOption{BasicOption: testBasic, Name: "out", Server: addr.Addr().String(), Port: int(addr.Port()), Password: user.Secret, Fingerprint: tlsFingerprint})
				require.NoError(t, err)
				return out
			},
		},
		{
			name:    "anytls",
			newUser: uuidUser,
			newIn: func(t *testing.T, name string, users []C.InboundUser) C.InboundListener {
				in, err := inbound.NewAnyTLS(&inbound.AnyTLSOption{BaseOption: base(name), Users: mapUsers(users), Certificate: tlsCertificate, PrivateKey: tlsPrivateKey})
				require.NoError(t, err)
				return in
			},
			newOut: func(t *testing.T, addr netip.AddrPort, user C.InboundUser) C.ProxyAdapter {
				out, err := outbound.NewAnyTLS(outbound.AnyTLSOption{BasicOption: testBasic, Name: "out", Server: addr.Addr().String(), Port: int(addr.Port()), Password: user.Secret, Fingerprint: tlsFingerprint})
				require.NoError(t, err)
				return out
			},
		},
		{
			name: "tuic",
			newUser: func(string) C.InboundUser {
				return C.InboundUser{Name: utils.NewUUIDV4().String(), Secret: utils.NewUUIDV4().String()}
			},
			newIn: func(t *testing.T, name string, users []C.InboundUser) C.InboundListener {
				in, err := inbound.NewTuic(&inbound.TuicOption{BaseOption: base(name), Users: mapUsers(users), Certificate: tlsCertificate, PrivateKey: tlsPrivateKey, AuthenticationTimeout: 5000})
				require.NoError(t, err)
				return in
			},
			newOut: func(t *testing.T, addr netip.AddrPort, user C.InboundUser) C.ProxyAdapter {
				out, err := outbound.NewTuic(outbound.TuicOption{Name: "out", Server: addr.Addr().String(), Port: int(addr.Port()), UUID: user.Name, Password: user.Secret, Fingerprint: tlsFingerprint})
				require.NoError(t, err)
				return out
			},
		},
		{
			name:    "trusttunnel",
			newUser: uuidUser,
			newIn: func(t *testing.T, name string, users []C.InboundUser) C.InboundListener {
				in, err := inbound.NewTrustTunnel(&inbound.TrustTunnelOption{BaseOption: base(name), Users: authUsers(users), Certificate: tlsCertificate, PrivateKey: tlsPrivateKey})
				require.NoError(t, err)
				return in
			},
			newOut: func(t *testing.T, addr netip.AddrPort, user C.InboundUser) C.ProxyAdapter {
				out, err := outbound.NewTrustTunnel(outbound.TrustTunnelOption{BasicOption: testBasic, Name: "out", Server: addr.Addr().String(), Port: int(addr.Port()), UserName: user.Name, Password: user.Secret, Fingerprint: tlsFingerprint})
				require.NoError(t, err)
				return out
			},
		},
		{
			name: "shadowsocks",
			newUser: func(name string) C.InboundUser {
				return C.InboundUser{Name: name, Secret: newSSKey(16)}
			},
			newIn: func(t *testing.T, name string, users []C.InboundUser) C.InboundListener {
				su := make([]inbound.ShadowSocksUser, len(users))
				for i, u := range users {
					su[i] = inbound.ShadowSocksUser{Name: u.Name, Password: u.Secret}
				}
				in, err := inbound.NewShadowSocks(&inbound.ShadowSocksOption{BaseOption: base(name), Cipher: "2022-blake3-aes-128-gcm", Password: runtimeUsersIPSK, Users: su})
				require.NoError(t, err)
				return in
			},
			newOut: func(t *testing.T, addr netip.AddrPort, user C.InboundUser) C.ProxyAdapter {
				out, err := outbound.NewShadowSocks(outbound.ShadowSocksOption{BasicOption: testBasic, Name: "out", Server: addr.Addr().String(), Port: int(addr.Port()), Cipher: "2022-blake3-aes-128-gcm", Password: runtimeUsersIPSK + ":" + user.Secret})
				require.NoError(t, err)
				return out
			},
		},
		{
			name:    "socks",
			newUser: uuidUser,
			newIn: func(t *testing.T, name string, users []C.InboundUser) C.InboundListener {
				in, err := inbound.NewSocks(&inbound.SocksOption{BaseOption: base(name), Users: authUsers(users)})
				require.NoError(t, err)
				return in
			},
			newOut: func(t *testing.T, addr netip.AddrPort, user C.InboundUser) C.ProxyAdapter {
				out, err := outbound.NewSocks5(outbound.Socks5Option{BasicOption: testBasic, Name: "out", Server: addr.Addr().String(), Port: int(addr.Port()), UserName: user.Name, Password: user.Secret})
				require.NoError(t, err)
				return out
			},
		},
		{
			name:    "http",
			newUser: uuidUser,
			newIn: func(t *testing.T, name string, users []C.InboundUser) C.InboundListener {
				in, err := inbound.NewHTTP(&inbound.HTTPOption{BaseOption: base(name), Users: authUsers(users)})
				require.NoError(t, err)
				return in
			},
			newOut: func(t *testing.T, addr netip.AddrPort, user C.InboundUser) C.ProxyAdapter {
				out, err := outbound.NewHttp(outbound.HttpOption{BasicOption: testBasic, Name: "out", Server: addr.Addr().String(), Port: int(addr.Port()), UserName: user.Name, Password: user.Secret})
				require.NoError(t, err)
				return out
			},
		},
		{
			name:    "mixed",
			newUser: uuidUser,
			newIn: func(t *testing.T, name string, users []C.InboundUser) C.InboundListener {
				in, err := inbound.NewMixed(&inbound.MixedOption{BaseOption: base(name), Users: authUsers(users)})
				require.NoError(t, err)
				return in
			},
			newOut: func(t *testing.T, addr netip.AddrPort, user C.InboundUser) C.ProxyAdapter {
				out, err := outbound.NewSocks5(outbound.Socks5Option{BasicOption: testBasic, Name: "out", Server: addr.Addr().String(), Port: int(addr.Port()), UserName: user.Name, Password: user.Secret})
				require.NoError(t, err)
				return out
			},
		},
	}
}

// setupRuntimeTunnel routes everything DIRECT, through a DIRECT without the
// loopback detector. The detector refuses an inbound connection whose source
// address is the local address of a DIRECT connection, taking it for DIRECT
// dialing back into the core. Over loopback, Linux hands the same ephemeral
// port to connections towards different destinations, so a client session
// to the inbound regularly gets the source port of a live DIRECT connection
// to the echo server and is refused: a false loop that has nothing to do with
// the users under test.
func setupRuntimeTunnel() {
	direct := &outbound.Direct{Base: outbound.NewBase(outbound.BaseOption{
		Name:   "DIRECT",
		Type:   C.Direct,
		UDP:    true,
		Prefer: C.DualStack,
	})}
	tunnel.UpdateProxies(map[string]C.Proxy{"DIRECT": adapter.NewProxy(direct)}, nil)
	tunnel.OnRunning()
}

// startRuntimeInbound registers in as a `listeners:` inbound and returns
// the address its clients dial (the TCP one).
func startRuntimeInbound(t *testing.T, in C.InboundListener) netip.AddrPort {
	listener.PatchInboundListeners(map[string]C.InboundListener{in.Name(): in}, tunnel.Tunnel, false)
	t.Cleanup(func() { listener.PatchInboundListeners(nil, tunnel.Tunnel, true) })
	addrs := splitAddrs(in.Address())
	require.NotEmpty(t, addrs, "inbound %s does not listen", in.Name())
	return netip.MustParseAddrPort(addrs[0])
}

// failsSoon reports whether a ping over conn fails within a few seconds:
// the server closed the session.
func failsSoon(conn net.Conn) bool {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ping(conn) != nil {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func names(users []C.InboundUser) []string {
	out := make([]string, len(users))
	for i, u := range users {
		out[i] = u.Name
	}
	return out
}

// TestInboundRuntimeUsers checks, for every protocol that supports it: a
// user added at runtime connects without a restart and the established
// sessions of the others survive; a removed user's session is closed and it
// can no longer connect; a re-keyed user's session is closed, its old secret
// fails and the new one works; the listener object is never recreated.
func TestInboundRuntimeUsers(t *testing.T) {
	setupRuntimeTunnel()
	echo := startEchoServer(t)
	for _, p := range runtimeUsersProtos() {
		p := p
		t.Run(p.name, func(t *testing.T) {
			name := "runtime-users-" + p.name
			alice, bob := p.newUser("alice"), p.newUser("bob")
			in := p.newIn(t, name, []C.InboundUser{alice})
			addr := startRuntimeInbound(t, in)
			newOut := func(user C.InboundUser) C.ProxyAdapter {
				out := p.newOut(t, addr, user)
				t.Cleanup(func() { _ = out.Close() })
				return out
			}

			aliceConn, err := echoSession(newOut(alice), echo)
			require.NoError(t, err, "alice connects")
			defer aliceConn.Close()

			// add bob at runtime
			require.NoError(t, listener.AddInboundUser(name, bob))
			bobConn, err := echoSession(newOut(bob), echo)
			require.NoError(t, err, "bob connects without a restart")
			defer bobConn.Close()
			require.NoError(t, ping(aliceConn), "alice's session survives the update")
			users, err := listener.InboundUsers(name)
			require.NoError(t, err)
			assert.ElementsMatch(t, []string{alice.Name, bob.Name}, names(users))

			// remove alice: her session is closed, she can no longer connect
			require.NoError(t, listener.RemoveInboundUser(name, alice.Name))
			assert.True(t, failsSoon(aliceConn), "alice's session is closed")
			_, err = echoSession(newOut(alice), echo)
			assert.Error(t, err, "removed alice cannot connect")
			require.NoError(t, ping(bobConn), "bob's session survives alice's removal")

			// re-key bob: his session is closed, the old secret fails
			rekeyed := p.newUser(bob.Name)
			rekeyed.Name = bob.Name
			require.NoError(t, listener.ModifyInboundUser(name, bob.Name, func(u *C.InboundUser) error {
				u.Secret = rekeyed.Secret
				return nil
			}))
			assert.True(t, failsSoon(bobConn), "bob's session with the old secret is closed")
			_, err = echoSession(newOut(bob), echo)
			assert.Error(t, err, "bob's old secret fails")
			conn, err := echoSession(newOut(rekeyed), echo)
			require.NoError(t, err, "bob's new secret works")
			_ = conn.Close()

			// the listener was updated in place
			users, err = listener.InboundUsers(name)
			require.NoError(t, err)
			assert.Equal(t, []string{bob.Name}, names(users))
			running, _ := listener.GetInbound(name)
			assert.Same(t, in, running, "the listener object is kept")
		})
	}
}

// TestInboundRuntimeUsersStats checks that a removal closes the tunnel
// connections of the user and retires its traffic counter, and that adding
// it back revives the counter.
func TestInboundRuntimeUsersStats(t *testing.T) {
	setupRuntimeTunnel()
	echo := startEchoServer(t)
	p := runtimeUsersProtos()[0] // vless
	name := "runtime-users-stats"
	alice := p.newUser("alice")
	in := p.newIn(t, name, []C.InboundUser{alice})
	addr := startRuntimeInbound(t, in)
	out := p.newOut(t, addr, alice)
	defer out.Close()

	conn, err := echoSession(out, echo)
	require.NoError(t, err)
	defer conn.Close()
	key := statistic.UserKey{Inbound: name, User: alice.Name}
	require.Eventually(t, func() bool {
		s, ok := statistic.DefaultManager.Users().Get(key)
		return ok && s.Conns == 1
	}, 5*time.Second, 20*time.Millisecond)

	require.NoError(t, listener.SetInboundUsers(name, nil))
	assert.Eventually(t, func() bool {
		s, ok := statistic.DefaultManager.Users().Get(key)
		return ok && s.Conns == 0
	}, 5*time.Second, 20*time.Millisecond, "the tunnel connection is closed")
	n := 0
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		if md := c.Info().Metadata; md.InName == name && md.InUser == alice.Name {
			n++
		}
		return true
	})
	assert.Zero(t, n, "no tracker of alice is left")

	// retired: the sweep drops it once drained
	statistic.DefaultManager.Users().DrainFunc(func(k statistic.UserKey) bool { return k == key })
	statistic.DefaultManager.Users().Sweep()
	_, ok := statistic.DefaultManager.Users().Get(key)
	assert.False(t, ok, "the counter of a removed user is retired")
}

// TestInboundRuntimeUsersConcurrent runs handshakes of several users while
// the users are replaced over and over (meant for -race): the users that
// stay keep connecting, nothing panics, and the final set is the last one
// applied.
func TestInboundRuntimeUsersConcurrent(t *testing.T) {
	setupRuntimeTunnel()
	echo := startEchoServer(t)
	for _, p := range runtimeUsersProtos() {
		p := p
		if p.name != "vless" && p.name != "trojan" && p.name != "shadowsocks" && p.name != "socks" {
			continue
		}
		t.Run(p.name, func(t *testing.T) {
			name := "runtime-users-race-" + p.name
			stable, flapping := p.newUser("stable"), p.newUser("flapping")
			in := p.newIn(t, name, []C.InboundUser{stable})
			addr := startRuntimeInbound(t, in)

			// bounded, so that a short run does not exhaust the ephemeral ports
			const sessions = 40
			done := make(chan struct{})
			var wg, updaters sync.WaitGroup
			var stableFailures atomic.Int64
			for i := 0; i < 3; i++ {
				wg.Add(2)
				go func() {
					defer wg.Done()
					out := p.newOut(t, addr, stable)
					defer out.Close()
					for j := 0; j < sessions; j++ {
						conn, err := echoSession(out, echo)
						if err != nil {
							t.Logf("stable session: %v", err)
							stableFailures.Add(1)
							continue
						}
						_ = conn.Close()
					}
				}()
				go func() {
					defer wg.Done()
					out := p.newOut(t, addr, flapping)
					defer out.Close()
					for j := 0; j < sessions; j++ {
						if conn, err := echoSession(out, echo); err == nil {
							_ = conn.Close()
						}
					}
				}()
			}
			updaters.Add(1)
			go func() {
				defer updaters.Done()
				for i := 0; ; i++ {
					select {
					case <-done:
						return
					default:
					}
					users := []C.InboundUser{stable}
					if i%2 == 0 {
						users = append(users, flapping)
					}
					assert.NoError(t, listener.SetInboundUsers(name, users))
					_, _ = listener.InboundUsers(name)
					time.Sleep(time.Millisecond)
				}
			}()
			wg.Wait()
			close(done)
			updaters.Wait()
			assert.Zero(t, stableFailures.Load(), "a user that stays is never refused")

			require.NoError(t, listener.SetInboundUsers(name, []C.InboundUser{stable}))
			_, err := echoSession(p.newOut(t, addr, flapping), echo)
			assert.Error(t, err, "the removed user is refused at the end")
		})
	}
}

// TestPatchInboundListenersUsersInPlace checks that a configuration reload
// whose listener differs only in its users updates the running listener in
// place (same object, sessions of the kept users survive), and that a reload
// with an unchanged configuration replaces the users changed at runtime.
func TestPatchInboundListenersUsersInPlace(t *testing.T) {
	setupRuntimeTunnel()
	echo := startEchoServer(t)
	p := runtimeUsersProtos()[0] // vless
	name := "runtime-users-patch"
	alice, bob, carol := p.newUser("alice"), p.newUser("bob"), p.newUser("carol")

	// a fixed port, so that the configurations differ only in the users
	free, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := fmt.Sprint(free.Addr().(*net.TCPAddr).Port)
	_ = free.Close()
	newIn := func(users ...C.InboundUser) C.InboundListener {
		vu := make([]inbound.VlessUser, len(users))
		for i, u := range users {
			vu[i] = inbound.VlessUser{Username: u.Name, UUID: u.Secret}
		}
		in, err := inbound.NewVless(&inbound.VlessOption{
			BaseOption:    inbound.BaseOption{NameStr: name, Listen: "127.0.0.1", Port: port},
			Users:         vu,
			AllowInsecure: true,
		})
		require.NoError(t, err)
		return in
	}
	reload := func(users ...C.InboundUser) C.InboundListener {
		next := newIn(users...)
		listener.PatchInboundListeners(map[string]C.InboundListener{name: next}, tunnel.Tunnel, true)
		return next
	}

	in := newIn(alice)
	addr := startRuntimeInbound(t, in)
	conn, err := echoSession(p.newOut(t, addr, alice), echo)
	require.NoError(t, err)
	defer conn.Close()

	// the configuration adds bob: only the users differ
	next := reload(alice, bob)
	running, _ := listener.GetInbound(name)
	assert.Same(t, in, running, "the running listener is kept")
	assert.NotSame(t, next, running)
	require.NoError(t, ping(conn), "alice's session survives the reload")
	bobConn, err := echoSession(p.newOut(t, addr, bob), echo)
	require.NoError(t, err, "bob from the new configuration connects")
	_ = bobConn.Close()

	// a runtime change is replaced by the next reload of the same configuration
	require.NoError(t, listener.AddInboundUser(name, carol))
	reload(alice, bob)
	users, err := listener.InboundUsers(name)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{alice.Name, bob.Name}, names(users))
	_, err = echoSession(p.newOut(t, addr, carol), echo)
	assert.Error(t, err, "carol, added at runtime, is gone after the reload")
	require.NoError(t, ping(conn), "alice's session survives")

	// another change than the users recreates the listener
	next, err = inbound.NewVless(&inbound.VlessOption{
		BaseOption:    inbound.BaseOption{NameStr: name, Listen: "127.0.0.1", Port: port},
		Users:         []inbound.VlessUser{{Username: alice.Name, UUID: alice.Secret}},
		AllowInsecure: true,
		WsPath:        "/ws",
	})
	require.NoError(t, err)
	_ = conn.Close() // the recreated listener needs the port
	listener.PatchInboundListeners(map[string]C.InboundListener{name: next}, tunnel.Tunnel, true)
	running, _ = listener.GetInbound(name)
	assert.Same(t, next, running, "a listener that changed more than its users is recreated")
}

// TestInboundRuntimeUsersErrors covers validation and unsupported inbounds.
func TestInboundRuntimeUsersErrors(t *testing.T) {
	setupRuntimeTunnel()
	p := runtimeUsersProtos()[0] // vless
	name := "runtime-users-errors"
	alice := p.newUser("alice")
	in := p.newIn(t, name, []C.InboundUser{alice})
	startRuntimeInbound(t, in)

	for _, users := range [][]C.InboundUser{
		{{Name: "", Secret: "x"}},
		{{Name: "a", Secret: ""}},
		{{Name: "a", Secret: "x"}, {Name: "a", Secret: "y"}},
		{{Name: "a", Secret: "x"}, {Name: "b", Secret: "x"}},
		{{Name: "a", Secret: "x", Flow: "bogus"}},
	} {
		err := listener.SetInboundUsers(name, users)
		assert.ErrorIs(t, err, C.ErrInvalidInboundUser, "%v", users)
	}
	assert.ErrorIs(t, listener.AddInboundUser(name, alice), listener.ErrInboundUserExists)
	assert.ErrorIs(t, listener.RemoveInboundUser(name, "nobody"), listener.ErrInboundUserNotFound)
	assert.ErrorIs(t, listener.SetInboundUsers("nope", nil), listener.ErrInboundNotFound)
	users, err := listener.InboundUsers(name)
	require.NoError(t, err)
	assert.Equal(t, []C.InboundUser{alice}, users, "a failed update changes nothing")

	// socks without users of its own and single-user shadowsocks cannot
	ss, err := inbound.NewShadowSocks(&inbound.ShadowSocksOption{
		BaseOption: inbound.BaseOption{NameStr: "runtime-users-ss-single", Listen: "127.0.0.1", Port: "0"},
		Cipher:     "2022-blake3-aes-128-gcm",
		Password:   newSSKey(16),
	})
	require.NoError(t, err)
	socks, err := inbound.NewSocks(&inbound.SocksOption{BaseOption: inbound.BaseOption{NameStr: "runtime-users-socks-global", Listen: "127.0.0.1", Port: "0"}})
	require.NoError(t, err)
	tun, err := inbound.NewTunnel(&inbound.TunnelOption{BaseOption: inbound.BaseOption{NameStr: "runtime-users-tunnel", Listen: "127.0.0.1", Port: "0"}, Network: []string{"tcp"}, Target: "127.0.0.1:1"})
	require.NoError(t, err)
	listener.PatchInboundListeners(map[string]C.InboundListener{ss.Name(): ss, socks.Name(): socks, tun.Name(): tun}, tunnel.Tunnel, false)
	for _, n := range []string{ss.Name(), socks.Name(), tun.Name()} {
		assert.ErrorIs(t, listener.SetInboundUsers(n, []C.InboundUser{{Name: "a", Secret: newSSKey(16)}}), C.ErrInboundUsersUnsupported, n)
	}
}
