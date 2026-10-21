package trojan

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/httputils"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/authevent"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/fallback"
	"github.com/metacubex/mihomo/listener/inbounduser"
	"github.com/metacubex/mihomo/listener/jls"
	"github.com/metacubex/mihomo/listener/reality"
	"github.com/metacubex/mihomo/listener/restls"
	"github.com/metacubex/mihomo/listener/shadowtls"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/gun"
	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/trojan"
	"github.com/metacubex/mihomo/transport/v2ray"

	"github.com/metacubex/http"
	"github.com/metacubex/smux"
	"github.com/metacubex/tls"
	"golang.org/x/exp/slices"
)

type Listener struct {
	closed     bool
	config     LC.TrojanServer
	listeners  []net.Listener
	users      *inbounduser.Set[[trojan.KeyLength]byte]
	pickCipher core.Cipher
	handler    *sing.ListenerHandler
	realIP     httputils.RealIP
}

func New(config LC.TrojanServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (sl *Listener, err error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-TROJAN"),
			inbound.WithSpecialRules(""),
		}
	}
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.TROJAN,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	users, _ := inbounduser.New(userKey, utils.Map(config.Users, func(it LC.TrojanUser) C.InboundUser {
		return C.InboundUser{Name: it.Username, Secret: it.Password}
	})) // userKey never fails

	var pickCipher core.Cipher
	if config.TrojanSSOption.Enabled {
		if config.TrojanSSOption.Password == "" {
			return nil, errors.New("empty password")
		}
		if config.TrojanSSOption.Method == "" {
			config.TrojanSSOption.Method = "AES-128-GCM"
		}
		pickCipher, err = core.PickCipher(config.TrojanSSOption.Method, nil, config.TrojanSSOption.Password)
		if err != nil {
			return nil, err
		}
	}
	realIP, err := httputils.NewRealIP(config.TrustedProxyHeader, config.TrustedProxies, false)
	if err != nil {
		return nil, err
	}
	if realIP.Header != "" && len(realIP.Trusted) == 0 {
		log.Warnln("[Trojan] %s: trusted-proxy-header %q is ignored until trusted-proxies lists the reverse proxies", config.Listen, realIP.Header)
	}

	sl = &Listener{false, config, nil, users, pickCipher, h, realIP}

	httpServer := http.Server{
		IdleTimeout: 30 * time.Second,
		// bounds the TLS handshake and the request header of ws/grpc/xhttp
		// before the conn reaches serveConn and its own handshake deadline
		ReadHeaderTimeout: handshakeTimeout.Load(),
		Protocols:         new(http.Protocols),
	}
	tlsConfig := &tls.Config{Time: ntp.Now, MinVersion: tls.VersionTLS12}
	var shadowTLSBuilder *shadowtls.Builder
	var restlsBuilder *restls.Builder
	var jlsBuilder *jls.Builder
	var realityBuilder *reality.Builder

	if config.Certificate != "" && config.PrivateKey != "" {
		certLoader, err := ca.NewTLSKeyPairLoader(config.Certificate, config.PrivateKey)
		if err != nil {
			return nil, err
		}
		tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return certLoader()
		}

		if config.EchKey != "" {
			err = ech.LoadECHKey(config.EchKey, tlsConfig)
			if err != nil {
				return nil, err
			}
		}
	}
	tlsConfig.ClientAuth = ca.ClientAuthTypeFromString(config.ClientAuthType)
	if len(config.ClientAuthCert) > 0 {
		if tlsConfig.ClientAuth == tls.NoClientCert {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	if tlsConfig.ClientAuth == tls.VerifyClientCertIfGiven || tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
		pool, err := ca.LoadCertificates(config.ClientAuthCert)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientCAs = pool
	}
	if tlsConfig.ClientAuth != tls.NoClientCert && tlsConfig.GetCertificate == nil {
		return nil, errors.New("client-auth requires certificate")
	}
	securityModes := make([]string, 0, 5)
	if tlsConfig.GetCertificate != nil {
		securityModes = append(securityModes, "certificate")
	}
	if config.RealityConfig.PrivateKey != "" {
		securityModes = append(securityModes, "reality")
	}
	if config.ShadowTLS.Enable {
		securityModes = append(securityModes, "shadow-tls")
	}
	if config.ResTLS.Enable {
		securityModes = append(securityModes, "res-tls")
	}
	if config.JLSConfig.Enable {
		securityModes = append(securityModes, "jls")
	}
	if len(securityModes) > 1 {
		return nil, errors.New("security modes are mutually exclusive: " + strings.Join(securityModes, ", "))
	}
	if config.RealityConfig.PrivateKey != "" {
		realityBuilder, err = config.RealityConfig.Build(tunnel)
		if err != nil {
			return nil, err
		}
	}
	if config.ShadowTLS.Enable {
		shadowTLSBuilder, err = shadowtls.New(config.ShadowTLS, tunnel)
		if err != nil {
			return nil, err
		}
	}
	if config.ResTLS.Enable {
		restlsBuilder = restls.New(config.ResTLS, tunnel)
	}
	if config.JLSConfig.Enable {
		jlsBuilder, err = jls.New(config.JLSConfig, tunnel)
		if err != nil {
			return nil, err
		}
	}
	// fallback-page: what a request that is not the inbound's own gets on an HTTP transport.
	// Only with one: a handler makes the listener serve HTTP, which plain Trojan does not.
	var page http.Handler
	if config.FallbackPage != "" && (config.WsPath != "" || config.GrpcServiceName != "") {
		if page, err = fallback.Page(config.FallbackPage); err != nil {
			return nil, err
		}
	}
	if config.WsPath != "" {
		httpServer.Handler = fallback.WebSocket(config.WsPath, page, func(w http.ResponseWriter, r *http.Request) {
			conn, err := v2ray.StreamUpgradedWebsocketConn(w, r)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			sl.HandleHTTPConn(r, conn, tunnel, additions...)
		})
		httpServer.Protocols.SetHTTP1(true)
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "http/1.1")
	}
	if config.GrpcServiceName != "" {
		other := httpServer.Handler
		if other == nil {
			other = page
		}
		httpServer.Handler = gun.NewServerHandler(gun.ServerOption{
			ServiceName: config.GrpcServiceName,
			ConnHandler: func(conn net.Conn, r *http.Request) {
				sl.HandleHTTPConn(r, conn, tunnel, additions...)
			},
			HttpHandler: other,
		})
		httpServer.Protocols.SetHTTP2(true)
		// SetUnencryptedHTTP2 to ensure we can work in plain http2 and some tls conn is not *tls.Conn (like *reality.Conn)
		//
		// Enable HTTP/2 support unconditionally on the server.
		//
		// Note that this usage is limited to our own net/http fork
		// The standard library also needs to mask the tls.Conn type for the conn returned by the Listener.
		// see: https://github.com/golang/go/issues/79293#issuecomment-4426393534
		httpServer.Protocols.SetUnencryptedHTTP2(true)
		tlsConfig.NextProtos = append([]string{"h2"}, tlsConfig.NextProtos...) // h2 must before http/1.1
	}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		//TCP
		l, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			return nil, err
		}
		if shadowTLSBuilder != nil {
			l = shadowTLSBuilder.NewListener(l)
		} else if restlsBuilder != nil {
			l = restlsBuilder.NewListener(l)
		} else if jlsBuilder != nil {
			l = jlsBuilder.NewListener(l)
		} else if realityBuilder != nil {
			l = realityBuilder.NewListener(l)
		} else if tlsConfig.GetCertificate != nil {
			l = tls.NewListener(l, tlsConfig)
		} else if !config.TrojanSSOption.Enabled && !config.AllowInsecure {
			return nil, errors.New("disallow using Trojan without any certificates/shadow-tls/res-tls/jls/reality/ss/allow-insecure config")
		}
		sl.listeners = append(sl.listeners, l)

		go func() {
			if httpServer.Handler != nil {
				_ = httpServer.Serve(l)
				return
			}
			for {
				c, err := l.Accept()
				if err != nil {
					if sl.closed {
						break
					}
					continue
				}

				go sl.HandleConn(c, tunnel, additions...)
			}
		}()
	}

	return sl, nil
}

func (l *Listener) Close() error {
	l.closed = true
	var retErr error
	for _, lis := range l.listeners {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	return retErr
}

func (l *Listener) Config() string {
	return l.config.String()
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.listeners {
		addrList = append(addrList, lis.Addr())
	}
	return
}

// userKey maps a user to its trojan key (the hex SHA-224 of the password).
func userKey(user C.InboundUser) ([trojan.KeyLength]byte, error) {
	return trojan.Key(user.Secret), nil
}

// Users returns the current users (Name = username, Secret = password).
func (l *Listener) Users() []C.InboundUser { return l.users.Users() }

// ReplaceUsers swaps the users without closing the listener; the sessions
// of the removed and changed users are closed.
func (l *Listener) ReplaceUsers(users []C.InboundUser) (inbounduser.Change, error) {
	if err := inbounduser.NoFlow("trojan", users); err != nil {
		return inbounduser.Change{}, err
	}
	return l.users.Replace(users)
}

func (l *Listener) HandleHTTPConn(r *http.Request, conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	if ap := l.realIP.ClientAddrPort(r); ap.IsValid() {
		additions = append(slices.Clip(additions), inbound.WithSrcAddrPort(ap))
		l.serveConn(conn, httputils.ClientNetAddr(ap, conn.RemoteAddr()), tunnel, additions...)
		return
	}
	l.HandleConn(conn, tunnel, additions...)
}

func (l *Listener) HandleConn(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	l.serveConn(conn, nil, tunnel, additions...)
}

// serveConn serves a trojan connection; client is the address of the client
// behind a trusted reverse proxy, nil when the TCP peer is the client.
func (l *Listener) serveConn(conn net.Conn, client net.Addr, tunnel C.Tunnel, additions ...inbound.Addition) {
	defer conn.Close()

	conn, additions, release, ok := l.authenticate(conn, client, additions)
	if !ok {
		return
	}
	defer release()
	l.handleConn(false, conn, tunnel, additions...)
}

// authenticate reads the password key and the CRLF after it, under the
// handshake deadline, and returns the conn to read the request from (behind
// the Trojan-SS cipher, if any), the additions with the user, and the release
// of the user binding.
//
// serveConn and handleConn stay on the stack of an idle session under the
// relay; this and readRequest keep their frames off it (see
// tunnel.dialTCPConn).
//
//go:noinline
func (l *Listener) authenticate(conn net.Conn, client net.Addr, additions []inbound.Addition) (net.Conn, []inbound.Addition, func(), bool) {
	// cleared by handleConn once the request header is read
	setHandshakeDeadline(conn)
	if l.pickCipher != nil {
		conn = l.pickCipher.StreamConn(conn)
	}

	var key [trojan.KeyLength]byte
	if _, err := io.ReadFull(conn, key[:]); err != nil {
		//log.Warnln("read key error: %s", err.Error())
		return nil, nil, nil, false
	}

	entry, ok := l.users.Lookup(key)
	if !ok {
		//log.Warnln("no such key")
		if client == nil {
			client = conn.RemoteAddr()
		}
		authevent.EmitAddr("trojan", authevent.ReasonWrongCredentials, conn.LocalAddr(), client)
		return nil, nil, nil, false
	}
	// the session dies with the user: removing or re-keying it closes conn
	release, bound := l.users.Bind(entry, conn)
	if !bound {
		return nil, nil, nil, false
	}
	additions = append(additions, inbound.WithInUser(entry.Name()))

	var crlf [2]byte
	if _, err := io.ReadFull(conn, crlf[:]); err != nil {
		//log.Warnln("read crlf error: %s", err.Error())
		release()
		return nil, nil, nil, false
	}
	return conn, additions, release, true
}

func (l *Listener) handleConn(inMux bool, conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	if inMux {
		defer conn.Close()
		// a mux stream must send its command and target in time too; the
		// outer conn's deadline was lifted when the session started
		setHandshakeDeadline(conn)
	}

	command, target, ok := readRequest(inMux, conn)
	if !ok {
		return
	}
	if command == trojan.CommandTCP {
		//tunnel.HandleTCPConn(inbound.NewSocket(target, conn, C.TROJAN, additions...))
		l.handler.HandleSocket(target, conn, additions...)
		return
	}
	l.handlePacketOrMux(inMux, command, conn, tunnel, additions...)
}

// readRequest reads the command and the target of a request, and the CRLF
// after them outside a mux session, and lifts the handshake deadline. A
// function of its own like authenticate.
//
//go:noinline
func readRequest(inMux bool, conn net.Conn) (byte, socks5.Addr, bool) {
	command, err := socks5.ReadByte(conn)
	if err != nil {
		//log.Warnln("read command error: %s", err.Error())
		return 0, nil, false
	}

	switch command {
	case trojan.CommandTCP, trojan.CommandUDP, trojan.CommandMux:
	default:
		//log.Warnln("unknown command: %d", command)
		return 0, nil, false
	}

	target, err := socks5.ReadAddr0(conn)
	if err != nil {
		//log.Warnln("read target error: %s", err.Error())
		return 0, nil, false
	}

	if !inMux {
		var crlf [2]byte
		if _, err := io.ReadFull(conn, crlf[:]); err != nil {
			//log.Warnln("read crlf error: %s", err.Error())
			return 0, nil, false
		}
	}
	// the header is read: lift the handshake deadline set by serveConn, or
	// above for a mux stream
	clearHandshakeDeadline(conn)
	return command, target, true
}

// handlePacketOrMux serves a UDP or a mux request.
func (l *Listener) handlePacketOrMux(inMux bool, command byte, conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	switch command {
	case trojan.CommandUDP:
		pc := trojan.NewPacketConn(conn)
		remoteAddr := conn.RemoteAddr()
		connID := utils.NewUUIDV4().String() // make a new SNAT key

		for {
			data, put, addr, err := pc.WaitReadFrom()
			if err != nil {
				if put != nil {
					put()
				}
				break
			}
			target := socks5.ParseAddrToSocksAddr(addr)
			cPacket := &packet{
				pc:      pc,
				rAddr:   remoteAddr,
				payload: data,
				put:     put,
			}
			cPacket.rAddr = N.NewCustomAddr(C.TROJAN.String(), connID, cPacket.rAddr) // for tunnel's handleUDPConn

			tunnel.HandleUDPPacket(inbound.NewPacket(target, cPacket, C.TROJAN, additions...))
		}
	case trojan.CommandMux:
		if inMux {
			//log.Warnln("invalid command: %d", command)
			return
		}
		smuxConfig := smux.DefaultConfig()
		smuxConfig.KeepAliveDisabled = true
		session, err := smux.Server(conn, smuxConfig)
		if err != nil {
			//log.Warnln("smux server error: %s", err.Error())
			return
		}
		defer session.Close()
		var streams atomic.Int32
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				return
			}
			if streams.Load() >= int32(maxMuxStreams) {
				// too many open streams: refuse this one (the client sees it
				// closed) rather than stall the session or spawn more
				_ = stream.Close()
				continue
			}
			streams.Add(1)
			go func() {
				defer streams.Add(-1)
				l.handleConn(true, stream, tunnel, additions...)
			}()
		}
	}
}
