package constant

import "errors"

// ErrRemovedProtocol wraps the errors for protocols and options Citrus dropped
// (ShadowsocksR, Hysteria v1, TUIC v4, Shadowsocks stream ciphers,
// v2ray-plugin, VMess). Providers skip such proxies with a warning instead of
// failing the whole provider, so one legacy node does not break a subscription.
var ErrRemovedProtocol = errors.New("removed from Citrus")

// ErrVMessRemoved is returned for VMess proxies, VMess listeners and the
// top-level vmess-config. It wraps ErrRemovedProtocol.
var ErrVMessRemoved error = removedError("VMess was removed from Citrus, use VLESS")

type removedError string

func (e removedError) Error() string { return string(e) }

func (e removedError) Unwrap() error { return ErrRemovedProtocol }
