package inbound

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_shadowsocks"
	"github.com/metacubex/mihomo/log"
)

type ShadowSocksOption struct {
	BaseOption
	Password   string            `inbound:"password"`
	Cipher     string            `inbound:"cipher"`
	Users      []ShadowSocksUser `inbound:"users,omitempty"`
	UDP        bool              `inbound:"udp,omitempty"`
	MuxOption  MuxOption         `inbound:"mux-option,omitempty"`
	ShadowTLS  ShadowTLS         `inbound:"shadow-tls,omitempty"`
	ResTLS     ResTLS            `inbound:"res-tls,omitempty"`
	JLSConfig  JLSConfig         `inbound:"jls-config,omitempty"`
	KcpTun     KcpTun            `inbound:"kcp-tun,omitempty"`
	SimpleObfs SimpleObfs        `inbound:"simple-obfs,omitempty"`
}

// ShadowSocksUser is one user of a multi-user Shadowsocks 2022 inbound (EIH).
// With users set, the inbound password is the server key (iPSK) and each
// user's password is its own key (uPSK); the client then uses "iPSK:uPSK".
type ShadowSocksUser struct {
	Name     string `inbound:"name"`
	Password string `inbound:"password"`
}

type SimpleObfs struct {
	Enable bool   `inbound:"enable,omitempty"`
	Mode   string `inbound:"mode,omitempty"`
}

func (o SimpleObfs) Build() LC.SimpleObfs {
	return LC.SimpleObfs{
		Enable: o.Enable,
		Mode:   o.Mode,
	}
}

func (o ShadowSocksOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type ShadowSocks struct {
	*Base
	config *ShadowSocksOption
	l      C.MultiAddrListener
	ss     LC.ShadowsocksServer
}

func NewShadowSocks(options *ShadowSocksOption) (*ShadowSocks, error) {
	base, err := newStreamBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	if base.IsUnix() {
		if options.UDP {
			return nil, errUnixUDP(options.Listen, "udp")
		}
		if options.KcpTun.Enable {
			return nil, errUnixUDP(options.Listen, "kcp-tun")
		}
	}
	users := make([]LC.ShadowsocksUser, len(options.Users))
	for i, u := range options.Users {
		users[i] = LC.ShadowsocksUser{Name: u.Name, Password: u.Password}
	}
	if err := sing_shadowsocks.ValidateUsers(options.Cipher, options.Password, users); err != nil {
		return nil, err
	}
	return &ShadowSocks{
		Base:   base,
		config: options,
		ss: LC.ShadowsocksServer{
			Enable:     true,
			Listen:     base.RawAddress(),
			Password:   options.Password,
			Cipher:     options.Cipher,
			Users:      users,
			Udp:        options.UDP,
			MuxOption:  options.MuxOption.Build(),
			ShadowTLS:  options.ShadowTLS.Build(),
			ResTLS:     options.ResTLS.Build(),
			JLSConfig:  options.JLSConfig.Build(),
			KcpTun:     options.KcpTun.Build(),
			SimpleObfs: options.SimpleObfs.Build(),
		},
	}, nil
}

// Config implements constant.InboundListener
func (s *ShadowSocks) Config() C.InboundConfig {
	return s.config
}

// Address implements constant.InboundListener
func (s *ShadowSocks) Address() string {
	var addrList []string
	if s.l != nil {
		for _, addr := range s.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (s *ShadowSocks) Listen(tunnel C.Tunnel) error {
	var err error
	s.l, err = sing_shadowsocks.New(s.ss, s.ListenConfig(), tunnel, s.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("ShadowSocks[%s] proxy listening at: %s", s.Name(), s.Address())
	return nil
}

// Close implements constant.InboundListener
func (s *ShadowSocks) Close() error {
	return s.l.Close()
}

var _ C.InboundListener = (*ShadowSocks)(nil)

// Users implements constant.InboundUserUpdater
func (s *ShadowSocks) Users() []C.InboundUser {
	return listenerUsers(s.l, func() []C.InboundUser { return s.configUsers() })
}

// SetUsers implements constant.InboundUserUpdater
func (s *ShadowSocks) SetUsers(users []C.InboundUser) error {
	return setListenerUsers(s.Name(), s.l, users)
}

// SameExceptUsers implements constant.InboundUserUpdater
func (s *ShadowSocks) SameExceptUsers(config C.InboundConfig) bool {
	// users switch the listener to multi-user mode: without users on both
	// sides it is not a change of users
	other, ok := config.(*ShadowSocksOption)
	return ok && len(s.config.Users) > 0 && len(other.Users) > 0 && equalExceptUsers(s.config, other)
}

var _ C.InboundUserUpdater = (*ShadowSocks)(nil)

func (s *ShadowSocks) configUsers() []C.InboundUser {
	users := make([]C.InboundUser, len(s.config.Users))
	for i, user := range s.config.Users {
		users[i] = C.InboundUser{Name: user.Name, Secret: user.Password}
	}
	return users
}

// InboundUsers implements constant.InboundUserLister
func (s *ShadowSocks) InboundUsers() []string { return userNames(s.Users()) }

var _ C.InboundUserLister = (*ShadowSocks)(nil)
