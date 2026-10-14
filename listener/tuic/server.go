package tuic

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/sockopt"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/inbounduser"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/tuic"
	v5 "github.com/metacubex/mihomo/transport/tuic/v5"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
	"golang.org/x/exp/slices"
)

// Per-connection QUIC stream limits. Streams over the limit are not refused:
// QUIC flow control (MAX_STREAMS) makes the client wait for a stream to close.
//
//   - Bidirectional streams carry one TCP relay each. The mihomo client opens
//     at most max-open-streams (100 by default) per connection before dialing
//     another one; single-connection clients get room for 2048 concurrent TCP
//     connections, far more than a phone or a home router uses.
//   - Unidirectional streams carry the authentication, heartbeats, dissociate
//     commands and, in the "quic" UDP relay mode, one stream per UDP packet.
//     Each lives for well under an RTT, so 2048 credits allow ~2048 packets
//     per RTT of UDP-over-stream.
//
// Before authentication the server additionally bounds the handlers it runs
// per connection (see tuic.ServerOption).
const (
	ServerMaxIncomingStreams    = 2048
	ServerMaxIncomingUniStreams = 2048
)

type Listener struct {
	closed       bool
	config       LC.TuicServer
	udpListeners []net.PacketConn
	servers      []*tuic.Server
	users        *inbounduser.Set[[16]byte]
}

func New(config LC.TuicServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	if len(config.Token) > 0 {
		return nil, fmt.Errorf("tuic-server: %w", tuic.ErrV4Unsupported)
	}
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-TUIC"),
			inbound.WithSpecialRules(""),
		}
	}
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.TUIC,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Time:       ntp.Now,
		MinVersion: tls.VersionTLS13,
	}
	certLoader, err := ca.NewTLSKeyPairLoader(config.Certificate, config.PrivateKey)
	if err != nil {
		return nil, err
	}
	tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return certLoader()
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

	if config.EchKey != "" {
		err = ech.LoadECHKey(config.EchKey, tlsConfig)
		if err != nil {
			return nil, err
		}
	}
	if len(config.ALPN) > 0 {
		tlsConfig.NextProtos = config.ALPN
	} else {
		tlsConfig.NextProtos = []string{"h3"}
	}

	if config.MaxIdleTime == 0 {
		config.MaxIdleTime = 15000
	}
	if config.AuthenticationTimeout == 0 {
		config.AuthenticationTimeout = 1000
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:        time.Duration(config.MaxIdleTime) * time.Millisecond,
		MaxIncomingStreams:    ServerMaxIncomingStreams,
		MaxIncomingUniStreams: ServerMaxIncomingUniStreams,
		EnableDatagrams:       true,
		Allow0RTT:             true,
		DisablePathManager:    true, // for port hopping
	}
	quicConfig.InitialStreamReceiveWindow = tuic.DefaultStreamReceiveWindow / 10
	quicConfig.MaxStreamReceiveWindow = tuic.DefaultStreamReceiveWindow
	quicConfig.InitialConnectionReceiveWindow = tuic.DefaultConnectionReceiveWindow / 10
	quicConfig.MaxConnectionReceiveWindow = tuic.DefaultConnectionReceiveWindow

	packetOverHead := tuic.PacketOverHeadV5

	if config.CWND == 0 {
		config.CWND = 32
	}

	if config.MaxUdpRelayPacketSize == 0 {
		config.MaxUdpRelayPacketSize = 1500
	}
	maxDatagramFrameSize := config.MaxUdpRelayPacketSize + packetOverHead
	if maxDatagramFrameSize > 1400 {
		maxDatagramFrameSize = 1400
	}
	config.MaxUdpRelayPacketSize = maxDatagramFrameSize - packetOverHead
	quicConfig.MaxDatagramFrameSize = int64(maxDatagramFrameSize)

	handleTcpFn := func(conn net.Conn, addr socks5.Addr, _additions ...inbound.Addition) error {
		//newAdditions := additions
		//if len(_additions) > 0 {
		//	newAdditions = slices.Clip(additions) // force the subsequent `append()` to copy the slice
		//	newAdditions = append(newAdditions, _additions...)
		//}
		//conn, metadata := inbound.NewSocket(addr, conn, C.TUIC, newAdditions...)
		//go tunnel.HandleTCPConn(conn, metadata)
		go h.HandleSocket(addr, conn, _additions...) // h.HandleSocket will block, so open a new goroutine
		return nil
	}
	handleUdpFn := func(addr socks5.Addr, packet C.UDPPacket, _additions ...inbound.Addition) error {
		newAdditions := additions
		if len(_additions) > 0 {
			newAdditions = slices.Clip(additions) // force the subsequent `append()` to copy the slice
			newAdditions = append(newAdditions, _additions...)
		}
		tunnel.HandleUDPPacket(inbound.NewPacket(addr, packet, C.TUIC, newAdditions...))
		return nil
	}

	option := &tuic.ServerOption{
		HandleTcpFn:           handleTcpFn,
		HandleUdpFn:           handleUdpFn,
		TlsConfig:             tlsConfig,
		QuicConfig:            quicConfig,
		CongestionController:  config.CongestionController,
		AuthenticationTimeout: time.Duration(config.AuthenticationTimeout) * time.Millisecond,
		MaxUdpRelayPacketSize: config.MaxUdpRelayPacketSize,
		CWND:                  config.CWND,
		BBRProfile:            config.BBRProfile,
	}
	option.Users, err = inbounduser.New(v5.UserKey, ConfigUsers(config.Users, true))
	if err != nil {
		return nil, err
	}

	sl := &Listener{false, config, nil, nil, option.Users}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		ul, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			return nil, err
		}

		if err := sockopt.UDPReuseaddr(ul); err != nil {
			log.Warnln("Failed to Reuse UDP Address: %s", err)
		}

		sl.udpListeners = append(sl.udpListeners, ul)

		var server *tuic.Server
		server, err = tuic.NewServer(option, ul)
		if err != nil {
			return nil, err
		}

		sl.servers = append(sl.servers, server)

		go func() {
			err := server.Serve()
			if err != nil {
				if sl.closed {
					return
				}
			}
		}()
	}

	return sl, nil
}

func (l *Listener) Close() error {
	l.closed = true
	var retErr error
	for _, lis := range l.servers {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	for _, lis := range l.udpListeners {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	return retErr
}

// ConfigUsers converts the users of a configuration (uuid -> password). The
// names become canonical lower-case UUIDs, the form of metadata.InUser; a
// name that is not a UUID can never authenticate and is left out.
func ConfigUsers(m map[string]string, warn bool) []C.InboundUser {
	users := make([]C.InboundUser, 0, len(m))
	for _, user := range inbounduser.FromMap(m) {
		id, err := uuid.FromString(user.Name)
		if err != nil {
			if warn {
				log.Warnln("tuic-server: user %q is not a UUID and can never authenticate", user.Name)
			}
			continue
		}
		user.Name = id.String()
		users = append(users, user)
	}
	return users
}

// Users returns the current users (Name = uuid, Secret = password).
func (l *Listener) Users() []C.InboundUser { return l.users.Users() }

// ReplaceUsers swaps the users without closing the listener; the QUIC
// connections of the removed and changed users are closed. The names are
// stored as canonical lower-case UUIDs, the form of metadata.InUser.
func (l *Listener) ReplaceUsers(users []C.InboundUser) (inbounduser.Change, error) {
	if err := inbounduser.NoFlow("tuic", users); err != nil {
		return inbounduser.Change{}, err
	}
	canonical := make([]C.InboundUser, len(users))
	for i, user := range users {
		if id, err := uuid.FromString(user.Name); err == nil {
			user.Name = id.String()
		}
		canonical[i] = user
	}
	return l.users.Replace(canonical)
}

func (l *Listener) Config() LC.TuicServer {
	return l.config
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.udpListeners {
		addrList = append(addrList, lis.LocalAddr())
	}
	return
}
