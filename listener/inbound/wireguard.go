package inbound

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/wireguard"
	"github.com/metacubex/mihomo/log"
)

// WireGuardOption is the `listeners:` entry of a WireGuard / AmneziaWG
// server. The node fills name, port, listen, users and private-key; a template
// may set the tunnel subnets, the MTU, the worker count and the obfuscation.
type WireGuardOption struct {
	BaseOption
	Users      map[string]string   `inbound:"users,omitempty"`
	PrivateKey string              `inbound:"private-key,omitempty"`
	MTU        int                 `inbound:"mtu,omitempty"`
	IPv4CIDR   string              `inbound:"ipv4-cidr,omitempty"`
	IPv6CIDR   string              `inbound:"ipv6-cidr,omitempty"`
	Workers    int                 `inbound:"workers,omitempty"`
	AmneziaWG  *LC.AmneziaWGServer `inbound:"amnezia-wg-option,omitempty"`
}

func (o WireGuardOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type WireGuard struct {
	*Base
	config *WireGuardOption
	l      *wireguard.Listener
	vs     LC.WireGuardServer
}

func NewWireGuard(options *WireGuardOption) (*WireGuard, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &WireGuard{
		Base:   base,
		config: options,
		vs: LC.WireGuardServer{
			Enable:     true,
			Listen:     base.RawAddress(),
			Users:      options.Users,
			PrivateKey: options.PrivateKey,
			MTU:        options.MTU,
			IPv4CIDR:   options.IPv4CIDR,
			IPv6CIDR:   options.IPv6CIDR,
			Workers:    options.Workers,
			AmneziaWG:  options.AmneziaWG,
		},
	}, nil
}

// Config implements constant.InboundListener
func (v *WireGuard) Config() C.InboundConfig { return v.config }

// Address implements constant.InboundListener
func (v *WireGuard) Address() string {
	if v.l == nil {
		return ""
	}
	var addrs []string
	for _, addr := range v.l.AddrList() {
		addrs = append(addrs, addr.String())
	}
	return strings.Join(addrs, ",")
}

// Listen implements constant.InboundListener
func (v *WireGuard) Listen(tunnel C.Tunnel) error {
	var err error
	v.l, err = wireguard.New(v.vs, v.ListenConfig(), tunnel, v.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("WireGuard[%s] proxy listening at: %s", v.Name(), v.Address())
	return nil
}

// Close implements constant.InboundListener
func (v *WireGuard) Close() error {
	if v.l == nil {
		return nil
	}
	return v.l.Close()
}

var _ C.InboundListener = (*WireGuard)(nil)

// Users implements constant.InboundUserUpdater
func (v *WireGuard) Users() []C.InboundUser {
	return listenerUsers(v.l, func() []C.InboundUser { return mapUsers(v.config.Users) })
}

// SetUsers implements constant.InboundUserUpdater
func (v *WireGuard) SetUsers(users []C.InboundUser) error {
	return setListenerUsers(v.Name(), v.l, users)
}

// SameExceptUsers implements constant.InboundUserUpdater
func (v *WireGuard) SameExceptUsers(config C.InboundConfig) bool {
	return equalExceptUsers(v.config, config)
}

var _ C.InboundUserUpdater = (*WireGuard)(nil)

// InboundUsers implements constant.InboundUserLister
func (v *WireGuard) InboundUsers() []string { return userNames(v.Users()) }

var _ C.InboundUserLister = (*WireGuard)(nil)
