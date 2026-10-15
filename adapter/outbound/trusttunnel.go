package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/trusttunnel"
	"github.com/metacubex/mihomo/transport/v2ray"
)

type TrustTunnel struct {
	*Base
	client *trusttunnel.PoolClient
	option *TrustTunnelOption
}

type TrustTunnelOption struct {
	BasicOption
	Name              string     `proxy:"name"`
	Server            string     `proxy:"server"`
	Port              int        `proxy:"port"`
	UserName          string     `proxy:"username,omitempty"`
	Password          string     `proxy:"password,omitempty"`
	ALPN              []string   `proxy:"alpn,omitempty"`
	SNI               string     `proxy:"sni,omitempty"`
	ECHOpts           ECHOptions `proxy:"ech-opts,omitempty"`
	ClientFingerprint string     `proxy:"client-fingerprint,omitempty"`
	SkipCertVerify    bool       `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify    string     `proxy:"name-cert-verify,omitempty"`
	Fingerprint       string     `proxy:"fingerprint,omitempty"`
	Certificate       string     `proxy:"certificate,omitempty"`
	PrivateKey        string     `proxy:"private-key,omitempty"`
	UDP               bool       `proxy:"udp,omitempty"`
	HealthCheck       bool       `proxy:"health-check,omitempty"`
	// quic options
	Quic                 bool   `proxy:"quic,omitempty"`
	CongestionController string `proxy:"congestion-controller,omitempty"`
	CWND                 int    `proxy:"cwnd,omitempty"`
	BBRProfile           string `proxy:"bbr-profile,omitempty"`
	// reuse options
	MaxConnections int `proxy:"max-connections,omitempty"`
	MinStreams     int `proxy:"min-streams,omitempty"`
	MaxStreams     int `proxy:"max-streams,omitempty"`
	// HTTP/2 session timers, in seconds; 0 means the default.
	PingInterval     int `proxy:"ping-interval,omitempty"` // -1 disables pings
	PingTimeout      int `proxy:"ping-timeout,omitempty"`
	HandshakeTimeout int `proxy:"handshake-timeout,omitempty"` // TCP dial and TLS handshake
}

// sessionTimers converts the HTTP/2 session timers of option to durations,
// leaving zero for the transport defaults and -1 for pings turned off.
func (option *TrustTunnelOption) sessionTimers() (pingInterval, pingTimeout, handshakeTimeout time.Duration, err error) {
	if option.PingInterval < -1 {
		return 0, 0, 0, fmt.Errorf("trusttunnel %s: ping-interval must be -1 (no pings), 0 (default) or at least 1 second, got %d", option.Name, option.PingInterval)
	}
	if option.PingTimeout < 0 {
		return 0, 0, 0, fmt.Errorf("trusttunnel %s: ping-timeout must be 0 (default) or at least 1 second, got %d", option.Name, option.PingTimeout)
	}
	if option.HandshakeTimeout < 0 {
		return 0, 0, 0, fmt.Errorf("trusttunnel %s: handshake-timeout must be 0 (default) or at least 1 second, got %d", option.Name, option.HandshakeTimeout)
	}
	return time.Duration(option.PingInterval) * time.Second,
		time.Duration(option.PingTimeout) * time.Second,
		time.Duration(option.HandshakeTimeout) * time.Second,
		nil
}

func (t *TrustTunnel) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := t.client.Dial(ctx, metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return NewConn(c, t), nil
}

func (t *TrustTunnel) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	pc, err := t.client.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}

	return NewPacketConn(N.NewThreadSafePacketConn(pc), t), nil
}

// SupportUOT implements C.ProxyAdapter
func (t *TrustTunnel) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (t *TrustTunnel) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (t *TrustTunnel) Close() error {
	return t.client.Close()
}

func NewTrustTunnel(option TrustTunnelOption) (*TrustTunnel, error) {
	pingInterval, pingTimeout, handshakeTimeout, err := option.sessionTimers()
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &TrustTunnel{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.TrustTunnel,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())

	tOption := trusttunnel.ClientOptions{
		Dialer:                outbound.dialer,
		DialOptions:           outbound.DialOptions,
		Server:                addr,
		Username:              option.UserName,
		Password:              option.Password,
		QUIC:                  option.Quic,
		QUICCongestionControl: option.CongestionController,
		QUICCwnd:              option.CWND,
		QUICBBRProfile:        option.BBRProfile,
		HealthCheck:           option.HealthCheck,
		MaxConnections:        option.MaxConnections,
		MinStreams:            option.MinStreams,
		MaxStreams:            option.MaxStreams,
		PingInterval:          pingInterval,
		PingTimeout:           pingTimeout,
		HandshakeTimeout:      handshakeTimeout,
	}
	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}
	tlsConfig := &v2ray.TLSConfig{
		Host:              option.SNI,
		SkipCertVerify:    option.SkipCertVerify,
		NameCertVerify:    option.NameCertVerify,
		NextProtos:        option.ALPN,
		FingerPrint:       option.Fingerprint,
		Certificate:       option.Certificate,
		PrivateKey:        option.PrivateKey,
		ClientFingerprint: option.ClientFingerprint,
		ECH:               echConfig,
	}
	if tlsConfig.Host == "" {
		tlsConfig.Host = option.Server
	}
	tOption.TLSConfig = tlsConfig

	client, err := trusttunnel.NewPoolClient(context.TODO(), tOption)
	if err != nil {
		return nil, err
	}
	outbound.client = client

	return outbound, nil
}
