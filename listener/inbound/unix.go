package inbound

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"strings"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
)

// unixListenerTypes lists the listener types that can listen on a unix socket,
// for the error a "unix:" listen address of another type gets.
const unixListenerTypes = "http, socks, mixed, shadowsocks, snell, vless, trojan, anytls, sudoku, trusttunnel, tunnel, hysteria2-realm"

// newUnixBase builds the base of a listener on the unix socket at path, from
// the listen address "unix:<path>". A relative path is resolved against the
// home directory.
func newUnixBase(options *BaseOption, path string) (*Base, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("listen %s: empty unix socket path", options.Listen)
	}
	if strings.Contains(path, ",") {
		return nil, fmt.Errorf("listen %s: a unix socket path cannot contain a comma", options.Listen)
	}
	if options.Port != "" {
		return nil, fmt.Errorf("listen %s: port cannot be used with a unix socket", options.Listen)
	}
	if options.RoutingMark != 0 {
		return nil, fmt.Errorf("listen %s: routing-mark cannot be used with a unix socket", options.Listen)
	}
	mode := inbound.DefaultUnixSocketMode
	if options.UnixMode != 0 {
		if options.UnixMode < 0 || options.UnixMode > 0o777 {
			return nil, fmt.Errorf("unix-mode %d: not a permission mask, write it in octal (0660, \"0o660\")", options.UnixMode)
		}
		mode = fs.FileMode(options.UnixMode)
	}
	return &Base{
		name:         options.Name(),
		specialRules: options.SpecialRules,
		unixPath:     C.Path.Resolve(path),
		unixMode:     mode,
		config:       options,
	}, nil
}

// unixListenConfig listens on the unix socket of a listener for the TCP
// listen request the listener makes for its address.
type unixListenConfig struct {
	address string // the listen address the listener asks for, "unix:<path>"
	path    string
	mode    fs.FileMode
}

func (c unixListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("listen %s: a unix socket cannot carry %s", c.address, network)
	}
	if address != c.address {
		return nil, fmt.Errorf("listen %s: unexpected listen address %s", c.address, address)
	}
	return inbound.ListenUnix(ctx, c.path, c.mode)
}

func (c unixListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return nil, fmt.Errorf("listen %s: a unix socket carries TCP streams only, %s cannot listen on it", c.address, network)
}

var _ C.InboundListenConfig = unixListenConfig{}

// errUnixUDP is returned for a UDP feature turned on for a unix socket listener.
func errUnixUDP(listen, feature string) error {
	return fmt.Errorf("listen %s: %s cannot be used with a unix socket, it carries TCP streams only", listen, feature)
}

// checkUnixNetworks rejects every network but TCP for a unix socket listener.
func checkUnixNetworks(base *Base, networks []string) error {
	if !base.IsUnix() {
		return nil
	}
	for _, network := range networks {
		if !strings.HasPrefix(strings.ToLower(network), "tcp") {
			return errUnixUDP(base.config.Listen, "network "+network)
		}
	}
	return nil
}

// IsUnixListen reports whether a listen address is a unix socket ("unix:<path>").
func IsUnixListen(listen string) bool {
	return strings.HasPrefix(listen, inbound.UnixSocketPrefix)
}
