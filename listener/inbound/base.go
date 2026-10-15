package inbound

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

type Base struct {
	config       *BaseOption
	name         string
	specialRules string
	listenAddr   netip.Addr
	ports        utils.IntRanges[uint16]
	// unixPath is the socket path when the listener listens on a unix socket
	unixPath string
	unixMode fs.FileMode
}

// NewBase builds the base of a listener that cannot listen on a unix socket:
// a "unix:" listen address is rejected.
func NewBase(options *BaseOption) (*Base, error) {
	return newBase(options, false)
}

// newStreamBase builds the base of a TCP stream listener, which may listen on
// a unix socket instead of TCP ports ("listen: unix:/path").
func newStreamBase(options *BaseOption) (*Base, error) {
	return newBase(options, true)
}

func newBase(options *BaseOption, allowUnix bool) (*Base, error) {
	if path, ok := strings.CutPrefix(options.Listen, inbound.UnixSocketPrefix); ok {
		if !allowUnix {
			return nil, fmt.Errorf("listen %s: this listener type cannot listen on a unix socket, only the TCP stream listeners can (%s)", options.Listen, unixListenerTypes)
		}
		return newUnixBase(options, path)
	}
	if options.UnixMode != 0 {
		return nil, errors.New("unix-mode needs a unix socket listen address (listen: unix:/path)")
	}
	if options.Listen == "" {
		options.Listen = "0.0.0.0"
	}
	addr, err := netip.ParseAddr(options.Listen)
	if err != nil {
		return nil, err
	}
	ports, err := utils.NewUnsignedRanges[uint16](options.Port)
	if err != nil {
		return nil, err
	}
	return &Base{
		name:         options.Name(),
		listenAddr:   addr,
		specialRules: options.SpecialRules,
		ports:        ports,
		config:       options,
	}, nil
}

// Config implements constant.InboundListener
func (b *Base) Config() C.InboundConfig {
	return b.config
}

// Address implements constant.InboundListener
func (b *Base) Address() string {
	return b.RawAddress()
}

// Close implements constant.InboundListener
func (*Base) Close() error {
	return nil
}

// Name implements constant.InboundListener
func (b *Base) Name() string {
	return b.name
}

// RawAddress implements constant.InboundListener
func (b *Base) RawAddress() string {
	if b.unixPath != "" {
		return inbound.UnixSocketPrefix + b.unixPath
	}
	if len(b.ports) == 0 {
		return net.JoinHostPort(b.listenAddr.String(), "0")
	}
	address := make([]string, 0, len(b.ports))
	b.ports.Range(func(port uint16) bool {
		address = append(address, net.JoinHostPort(b.listenAddr.String(), strconv.Itoa(int(port))))
		return true
	})
	return strings.Join(address, ",")
}

// Listen implements constant.InboundListener
func (*Base) Listen(tunnel C.Tunnel) error {
	return nil
}

func (b *Base) Additions() []inbound.Addition {
	return b.config.Additions()
}

func (b *Base) ListenConfig() C.InboundListenConfig {
	if b.unixPath != "" {
		return unixListenConfig{address: b.RawAddress(), path: b.unixPath, mode: b.unixMode}
	}
	return b.config.ListenConfig()
}

// IsUnix reports whether the listener listens on a unix socket.
func (b *Base) IsUnix() bool {
	return b.unixPath != ""
}

var _ C.InboundListener = (*Base)(nil)

type BaseOption struct {
	NameStr      string `inbound:"name"`
	Listen       string `inbound:"listen,omitempty"`
	Port         string `inbound:"port,omitempty"`
	SpecialRules string `inbound:"rule,omitempty"`
	SpecialProxy string `inbound:"proxy,omitempty"`
	RoutingMark  int    `inbound:"routing-mark,omitempty"`
	// UnixMode is the permission mask of the socket of a "unix:" listen
	// address, 0660 when unset.
	UnixMode int `inbound:"unix-mode,omitempty"`

	//
	// The following parameters are used internally, assign value by the structure decoder are disallowed
	//
	ListenConfigForAPI C.InboundListenConfig `inbound:"-"`
}

func (o BaseOption) Name() string {
	return o.NameStr
}

func (o BaseOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

func (o BaseOption) Additions() []inbound.Addition {
	return []inbound.Addition{
		inbound.WithInName(o.NameStr),
		inbound.WithSpecialRules(o.SpecialRules),
		inbound.WithSpecialProxy(o.SpecialProxy),
	}
}

func (o BaseOption) ListenConfig() C.InboundListenConfig {
	if o.ListenConfigForAPI != nil {
		return o.ListenConfigForAPI
	}
	lc := inbound.NewListenConfig()
	lc.SetRouteMark(o.RoutingMark)
	return lc
}

var _ C.InboundConfig = (*BaseOption)(nil)

func optionToString(option any) string {
	str, _ := json.Marshal(option)
	return string(str)
}
