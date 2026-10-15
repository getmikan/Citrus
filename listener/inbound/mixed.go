package inbound

import (
	"errors"
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/mixed"
	"github.com/metacubex/mihomo/listener/socks"
	"github.com/metacubex/mihomo/log"
)

type MixedOption struct {
	BaseOption
	Users          AuthUsers     `inbound:"users,omitempty"`
	UDP            bool          `inbound:"udp,omitempty"`
	Certificate    string        `inbound:"certificate,omitempty"`
	PrivateKey     string        `inbound:"private-key,omitempty"`
	ClientAuthType string        `inbound:"client-auth-type,omitempty"`
	ClientAuthCert string        `inbound:"client-auth-cert,omitempty"`
	EchKey         string        `inbound:"ech-key,omitempty"`
	RealityConfig  RealityConfig `inbound:"reality-config,omitempty"`
}

func (o MixedOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Mixed struct {
	*Base
	authStoreUsers
	config *MixedOption
	l      []*mixed.Listener
	lUDP   []*socks.UDPListener
	udp    bool
}

func NewMixed(options *MixedOption) (*Mixed, error) {
	base, err := newStreamBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	if base.IsUnix() && options.UDP {
		return nil, errUnixUDP(options.Listen, "udp")
	}
	users, err := newAuthStoreUsers(base.Name(), options.Users)
	if err != nil {
		return nil, err
	}
	return &Mixed{
		Base:           base,
		config:         options,
		udp:            options.UDP,
		authStoreUsers: users,
	}, nil
}

// Config implements constant.InboundListener
func (m *Mixed) Config() C.InboundConfig {
	return m.config
}

// Address implements constant.InboundListener
func (m *Mixed) Address() string {
	var addrList []string
	for _, l := range m.l {
		addrList = append(addrList, l.Address())
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (m *Mixed) Listen(tunnel C.Tunnel) error {
	lc := m.ListenConfig()
	for _, addr := range strings.Split(m.RawAddress(), ",") {
		config := LC.AuthServer{
			Enable:         true,
			Listen:         addr,
			AuthStore:      m.authStore(),
			Certificate:    m.config.Certificate,
			PrivateKey:     m.config.PrivateKey,
			ClientAuthType: m.config.ClientAuthType,
			ClientAuthCert: m.config.ClientAuthCert,
			EchKey:         m.config.EchKey,
			RealityConfig:  m.config.RealityConfig.Build(),
		}
		l, err := mixed.NewWithConfig(config, lc, tunnel, m.Additions()...)
		if err != nil {
			return err
		}
		m.l = append(m.l, l)
		if m.udp {
			lUDP, err := socks.NewUDPWithConfig(config, lc, tunnel, m.Additions()...)
			if err != nil {
				return err
			}
			m.lUDP = append(m.lUDP, lUDP)
		}
	}
	log.Infoln("Mixed(http+socks)[%s] proxy listening at: %s", m.Name(), m.Address())
	return nil
}

// Close implements constant.InboundListener
func (m *Mixed) Close() error {
	var errs []error
	for _, l := range m.l {
		err := l.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("close tcp listener %s err: %w", l.Address(), err))
		}
	}
	for _, l := range m.lUDP {
		err := l.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("close udp listener %s err: %w", l.Address(), err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

var _ C.InboundListener = (*Mixed)(nil)

// SameExceptUsers implements constant.InboundUserUpdater: only between
// configurations that both have users of their own (no users means the
// global authentication, `users: []` turns it off).
func (m *Mixed) SameExceptUsers(config C.InboundConfig) bool {
	other, ok := config.(*MixedOption)
	return ok && m.store != nil && len(other.Users) > 0 && equalExceptUsers(m.config, other)
}

var _ C.InboundUserUpdater = (*Mixed)(nil)
var _ C.InboundUserLister = (*Mixed)(nil)
