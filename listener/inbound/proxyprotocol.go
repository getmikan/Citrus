package inbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/metacubex/mihomo/common/httputils"
	"github.com/metacubex/mihomo/common/proxyproto"
	C "github.com/metacubex/mihomo/constant"
)

// proxyProtocolConfig validates proxy-protocol and proxy-protocol-trusted and
// returns the config of the PROXY protocol listener, nil when it is off.
func (o *BaseOption) proxyProtocolConfig(stream bool) (*proxyproto.Config, error) {
	if !o.ProxyProtocol {
		if len(o.ProxyProtocolTrusted) > 0 {
			return nil, errors.New("proxy-protocol-trusted needs proxy-protocol: true")
		}
		return nil, nil
	}
	if !stream {
		return nil, fmt.Errorf("proxy-protocol: this listener type does not accept TCP streams, only the TCP stream listeners can (%s)", unixListenerTypes)
	}
	trusted, err := httputils.ParseTrustedProxies(o.ProxyProtocolTrusted)
	if err != nil {
		return nil, fmt.Errorf("proxy-protocol-trusted: %w", err)
	}
	return &proxyproto.Config{Trusted: trusted}, nil
}

// proxyProtocolListenConfig reads the PROXY protocol header of every TCP
// connection the listeners accept from the listener they ask for. The
// listeners know nothing about it: the address they see is the client's. UDP
// has no header, ListenPacket is left alone.
type proxyProtocolListenConfig struct {
	C.InboundListenConfig
	config proxyproto.Config
}

func (c proxyProtocolListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	l, err := c.InboundListenConfig.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(network, "tcp") {
		return l, nil
	}
	return proxyproto.NewListener(l, c.config), nil
}
