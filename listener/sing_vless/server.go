package sing_vless

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/httputils"
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
	"github.com/metacubex/mihomo/transport/v2ray"
	"github.com/metacubex/mihomo/transport/vless/encryption"
	"github.com/metacubex/mihomo/transport/xdrive"
	"github.com/metacubex/mihomo/transport/xhttp"

	"github.com/metacubex/http"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
	"golang.org/x/exp/slices"
)

type Listener struct {
	closed     bool
	config     LC.VlessServer
	listeners  []net.Listener
	service    *Service
	decryption *encryption.ServerInstance
	realIP     httputils.RealIP
}

func New(config LC.VlessServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (sl *Listener, err error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-VLESS"),
			inbound.WithSpecialRules(""),
		}
	}
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.VLESS,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	service := NewService(h, common.Map(config.Users, func(it LC.VlessUser) C.InboundUser {
		return C.InboundUser{Name: it.Username, Secret: it.UUID, Flow: it.Flow}
	}))

	realIP, err := httputils.NewRealIP(config.TrustedProxyHeader, config.TrustedProxies, false)
	if err != nil {
		return nil, err
	}
	if realIP.Header != "" && len(realIP.Trusted) == 0 {
		log.Warnln("[VLESS] %s: trusted-proxy-header %q is ignored until trusted-proxies lists the reverse proxies", config.Listen, realIP.Header)
	}

	sl = &Listener{config: config, service: service, realIP: realIP}

	sl.decryption, err = encryption.NewServer(config.Decryption)
	if err != nil {
		return nil, err
	}
	if sl.decryption != nil {
		decryption := sl.decryption
		defer func() { // decryption must be closed to avoid the goroutine leak
			if err != nil {
				_ = decryption.Close()
			}
		}()
	}

	if config.XDriveConfig != nil {
		if sl.decryption == nil {
			return nil, errors.New("xdrive requires VLESS decryption")
		}
		for _, user := range config.Users {
			if user.Flow != "" {
				return nil, errors.New("xdrive does not support VLESS flow")
			}
		}
		if strings.Contains(config.Listen, ",") {
			return nil, errors.New("xdrive requires exactly one listener address")
		}
		if config.WsPath != "" || config.GrpcServiceName != "" || config.XHTTPConfig != (LC.XHTTPConfig{}) || config.Certificate != "" || config.PrivateKey != "" || config.RealityConfig.PrivateKey != "" || config.ShadowTLS.Password != "" || config.ResTLS.Password != "" || config.JLSConfig.Enable {
			return nil, errors.New("xdrive cannot be combined with TCP transport or server TLS settings")
		}
		storageListener, err := xdrive.Listen(*config.XDriveConfig, nil)
		if err != nil {
			return nil, err
		}
		sl.listeners = append(sl.listeners, storageListener)
		go func() {
			for {
				conn, err := storageListener.Accept()
				if err != nil {
					return
				}
				go sl.HandleConn(conn, tunnel)
			}
		}()
		return sl, nil
	}

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
	xhttpOn := config.XHTTPConfig.Path != "" || config.XHTTPConfig.Host != "" || config.XHTTPConfig.Mode != ""
	// fallback-page: what a request that is not the inbound's own gets on an HTTP transport.
	// Only with one: a handler makes the listener serve HTTP, which plain VLESS does not.
	var page http.Handler
	if config.FallbackPage != "" && (config.WsPath != "" || config.GrpcServiceName != "" || xhttpOn) {
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
	if config.XHTTPConfig.Mode != "" {
		switch config.XHTTPConfig.Mode {
		case "auto", "stream-up", "stream-one", "packet-up":
		default:
			return nil, errors.New("unsupported xhttp mode")
		}
	}
	if config.XHTTPConfig.ServerMaxHeaderBytes < 0 {
		return nil, errors.New("invalid negative value of xhttp server-max-header-bytes")
	}
	if xhttpOn {
		httpServer.Handler, err = xhttp.NewServerHandler(xhttp.ServerOption{
			Config: xhttp.Config{
				Host:                 config.XHTTPConfig.Host,
				Path:                 config.XHTTPConfig.Path,
				Mode:                 config.XHTTPConfig.Mode,
				XPaddingBytes:        config.XHTTPConfig.XPaddingBytes,
				XPaddingObfsMode:     config.XHTTPConfig.XPaddingObfsMode,
				XPaddingKey:          config.XHTTPConfig.XPaddingKey,
				XPaddingHeader:       config.XHTTPConfig.XPaddingHeader,
				XPaddingPlacement:    config.XHTTPConfig.XPaddingPlacement,
				XPaddingMethod:       config.XHTTPConfig.XPaddingMethod,
				UplinkHTTPMethod:     config.XHTTPConfig.UplinkHTTPMethod,
				SessionPlacement:     config.XHTTPConfig.SessionPlacement,
				SessionKey:           config.XHTTPConfig.SessionKey,
				SeqPlacement:         config.XHTTPConfig.SeqPlacement,
				SeqKey:               config.XHTTPConfig.SeqKey,
				UplinkDataPlacement:  config.XHTTPConfig.UplinkDataPlacement,
				UplinkDataKey:        config.XHTTPConfig.UplinkDataKey,
				UplinkChunkSize:      config.XHTTPConfig.UplinkChunkSize,
				NoSSEHeader:          config.XHTTPConfig.NoSSEHeader,
				ScStreamUpServerSecs: config.XHTTPConfig.ScStreamUpServerSecs,
				ScMaxBufferedPosts:   config.XHTTPConfig.ScMaxBufferedPosts,
				ScMaxEachPostBytes:   config.XHTTPConfig.ScMaxEachPostBytes,
			},
			ConnHandler: func(conn net.Conn, r *http.Request) {
				sl.HandleHTTPConn(r, conn, tunnel, additions...)
			},
			HttpHandler: httpServer.Handler,
			Fallback:    page,
			// NewConnection reports the authenticated user through the
			// request's OnAuthenticated (HandleHTTPConn passes it on)
			ReportsAuthentication: true,
		})
		if err != nil {
			return nil, err
		}
		// server-max-header-bytes (Xray-core serverMaxHeaderBytes) limits the request
		// header size for h1 and, as SETTINGS_MAX_HEADER_LIST_SIZE, for h2. Raise it when
		// uplink-data-placement puts packet-up data into headers or cookies.
		// Unset keeps the net/http default (1 MiB), which is above Xray-core's 8192.
		if config.XHTTPConfig.ServerMaxHeaderBytes > 0 {
			httpServer.MaxHeaderBytes = config.XHTTPConfig.ServerMaxHeaderBytes
		}
		httpServer.Protocols.SetHTTP1(true)
		httpServer.Protocols.SetHTTP2(true)
		// SetUnencryptedHTTP2 to ensure we can work in plain http2 and some tls conn is not *tls.Conn (like *reality.Conn)
		//
		// Enable HTTP/2 support unconditionally on the server.
		//
		// Note that this usage is limited to our own net/http fork
		// The standard library also needs to mask the tls.Conn type for the conn returned by the Listener.
		// see: https://github.com/golang/go/issues/79293#issuecomment-4426393534
		httpServer.Protocols.SetUnencryptedHTTP2(true)
		if !slices.Contains(tlsConfig.NextProtos, "http/1.1") {
			tlsConfig.NextProtos = append([]string{"http/1.1"}, tlsConfig.NextProtos...)
		}
		if !slices.Contains(tlsConfig.NextProtos, "h2") {
			tlsConfig.NextProtos = append([]string{"h2"}, tlsConfig.NextProtos...)
		}
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
		} else if sl.decryption == nil && !config.AllowInsecure {
			return nil, errors.New("disallow using Vless without any certificates/shadow-tls/res-tls/jls/reality/decryption/allow-insecure config")
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

				go sl.HandleConn(c, tunnel)
			}
		}()
	}

	return sl, nil
}

// Users returns the current users.
func (l *Listener) Users() []C.InboundUser { return l.service.Users() }

// ReplaceUsers swaps the users without closing the listener.
func (l *Listener) ReplaceUsers(users []C.InboundUser) (inbounduser.Change, error) {
	if l.config.XDriveConfig != nil {
		for _, user := range users {
			if user.Flow != "" {
				return inbounduser.Change{}, errors.New("xdrive does not support VLESS flow")
			}
		}
	}
	return l.service.ReplaceUsers(users)
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
	if l.decryption != nil {
		_ = l.decryption.Close()
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

func (l *Listener) HandleHTTPConn(r *http.Request, conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	onAuthenticated := xhttp.OnAuthenticated(r)
	if ap := l.realIP.ClientAddrPort(r); ap.IsValid() {
		additions = append(slices.Clip(additions), inbound.WithSrcAddrPort(ap))
		l.serveConnAuth(conn, httputils.ClientNetAddr(ap, conn.RemoteAddr()), onAuthenticated, tunnel, additions...)
		return
	}
	l.serveConnAuth(conn, nil, onAuthenticated, tunnel, additions...)
}

func (l *Listener) HandleConn(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	l.serveConn(conn, nil, tunnel, additions...)
}

// serveConn serves a vless connection; client is the address of the client
// behind a trusted reverse proxy, nil when the TCP peer is the client.
func (l *Listener) serveConn(conn net.Conn, client net.Addr, tunnel C.Tunnel, additions ...inbound.Addition) {
	l.serveConnAuth(conn, client, nil, tunnel, additions...)
}

// serveConnAuth is serveConn with onAuthenticated, called (if not nil) once
// the user is authenticated.
func (l *Listener) serveConnAuth(conn net.Conn, client net.Addr, onAuthenticated func(), tunnel C.Tunnel, additions ...inbound.Addition) {
	ctx := sing.WithAdditions(context.TODO(), additions...)
	if client != nil {
		ctx = withClientAddr(ctx, client)
	}
	if onAuthenticated != nil {
		ctx = withOnAuthenticated(ctx, onAuthenticated)
	}
	// cleared by NewConnection once the request header is read and the user
	// is authenticated
	setHandshakeDeadline(conn)
	if l.decryption != nil {
		c, err := l.decryption.Handshake(conn, nil)
		if err != nil {
			_ = conn.Close()
			return
		}
		conn = c
	}
	err := l.service.NewConnection(ctx, conn, metadata.Metadata{
		Protocol: "vless",
		Source:   metadata.SocksaddrFromNet(conn.RemoteAddr()),
	})
	if err != nil {
		_ = conn.Close()
		return
	}
}
