package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync/atomic"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/component/authevent"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/inbounduser"
	"github.com/metacubex/mihomo/listener/jls"
	"github.com/metacubex/mihomo/listener/restls"
	"github.com/metacubex/mihomo/listener/shadowtls"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/session"

	"github.com/metacubex/sing/common/auth"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

type Listener struct {
	closed    bool
	config    LC.AnyTLSServer
	listeners []net.Listener
	tlsConfig *tls.Config
	users     *inbounduser.Set[[32]byte]
	padding   atomic.Pointer[padding.PaddingFactory]
}

func New(config LC.AnyTLSServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (sl *Listener, err error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-ANYTLS"),
			inbound.WithSpecialRules(""),
		}
	}

	var shadowTLSBuilder *shadowtls.Builder
	var restlsBuilder *restls.Builder
	var jlsBuilder *jls.Builder
	tlsConfig := &tls.Config{Time: ntp.Now, MinVersion: tls.VersionTLS12}
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
	securityModes := make([]string, 0, 4)
	if tlsConfig.GetCertificate != nil {
		securityModes = append(securityModes, "certificate")
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

	sl = &Listener{
		config:    config,
		tlsConfig: tlsConfig,
	}
	sl.users, _ = inbounduser.New(userKey, inbounduser.FromMap(config.Users)) // userKey never fails

	if len(config.PaddingScheme) > 0 {
		if !padding.UpdatePaddingScheme([]byte(config.PaddingScheme), &sl.padding) {
			return nil, errors.New("incorrect padding scheme format")
		}
	} else {
		padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &sl.padding)
	}

	// Using sing handler can automatically handle UoT
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.ANYTLS,
		Additions: additions,
	})
	if err != nil {
		return nil, err
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
		} else if tlsConfig.GetCertificate != nil {
			l = tls.NewListener(l, tlsConfig)
		} else if !config.AllowInsecure {
			return nil, errors.New("disallow using AnyTLS without certificates/shadow-tls/res-tls/jls/allow-insecure config")
		}
		sl.listeners = append(sl.listeners, l)

		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					if sl.closed {
						break
					}
					continue
				}
				go sl.HandleConn(c, h)
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

// userKey maps a user to the SHA-256 of its password.
func userKey(user C.InboundUser) ([32]byte, error) {
	return sha256.Sum256([]byte(user.Secret)), nil
}

// Users returns the current users (Name = user, Secret = password).
func (l *Listener) Users() []C.InboundUser { return l.users.Users() }

// ReplaceUsers swaps the users without closing the listener; the sessions
// of the removed and changed users are closed.
func (l *Listener) ReplaceUsers(users []C.InboundUser) (inbounduser.Change, error) {
	if err := inbounduser.NoFlow("anytls", users); err != nil {
		return inbounduser.Change{}, err
	}
	return l.users.Replace(users)
}

func (l *Listener) HandleConn(conn net.Conn, h *sing.ListenerHandler) {
	defer conn.Close()

	conn, ctx, release, ok := l.authenticate(conn)
	if !ok {
		return
	}
	defer release()

	session := session.NewServerSession(conn, func(stream *session.Stream) {
		defer stream.Close()

		// a stream that never sends its destination must not hold its
		// goroutine forever
		setHandshakeDeadline(stream)
		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			return
		}
		clearHandshakeDeadline(stream)

		// It seems that mihomo does not implement a connection error reporting mechanism, so we report success directly.
		err = stream.HandshakeSuccess()
		if err != nil {
			return
		}

		h.NewConnection(ctx, stream, M.Metadata{
			Source:      M.SocksaddrFromNet(conn.RemoteAddr()),
			Destination: destination,
		})
	}, &l.padding)
	session.Run()
	session.Close()
}

// authenticate reads the password hash and the padding of the first packet,
// under the handshake deadline, and returns the conn to run the session on
// (with the rest of that packet cached), the context with the user, and the
// release of the user binding.
//
// The session's goroutine waits for frames under HandleConn for as long as
// the session lives; this keeps the frame of the authentication off its
// stack (see session.(*Session).handleFrame).
//
//go:noinline
func (l *Listener) authenticate(conn net.Conn) (net.Conn, context.Context, func(), bool) {
	ctx := context.TODO()

	b := buf.NewPacket()
	defer b.Release()

	setHandshakeDeadline(conn)
	_, err := b.ReadOnceFrom(conn)
	if err != nil {
		return nil, nil, nil, false
	}
	conn = bufio.NewCachedConn(conn, b)

	by, err := b.ReadBytes(32)
	if err != nil {
		return nil, nil, nil, false
	}
	var passwordSha256 [32]byte
	copy(passwordSha256[:], by)
	entry, ok := l.users.Lookup(passwordSha256)
	if !ok {
		authevent.EmitAddr("anytls", authevent.ReasonWrongCredentials, conn.LocalAddr(), conn.RemoteAddr())
		return nil, nil, nil, false
	}
	ctx = auth.ContextWithUser(ctx, entry.Name())
	// the session dies with the user: removing or re-keying it closes conn
	release, bound := l.users.Bind(entry, conn)
	if !bound {
		return nil, nil, nil, false
	}
	by, err = b.ReadBytes(2)
	if err != nil {
		release()
		return nil, nil, nil, false
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		_, err = b.ReadBytes(int(paddingLen))
		if err != nil {
			release()
			return nil, nil, nil, false
		}
	}
	clearHandshakeDeadline(conn)
	return conn, ctx, release, true
}
