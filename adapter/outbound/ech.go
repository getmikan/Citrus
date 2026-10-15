package outbound

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/dns"
)

type ECHOptions struct {
	Enable bool   `proxy:"enable,omitempty" obfs:"enable,omitempty"`
	Config string `proxy:"config,omitempty" obfs:"config,omitempty"`

	QueryServerName string `proxy:"query-server-name,omitempty" obfs:"query-server-name,omitempty"`
	// QueryServer is a DNS server (nameserver syntax, e.g. https://1.1.1.1/dns-query
	// or udp://8.8.8.8) to query the HTTPS record with the ECH config from,
	// instead of the proxy-server-nameserver / default resolver.
	QueryServer string `proxy:"query-server,omitempty" obfs:"query-server,omitempty"`
}

func (o ECHOptions) Parse() (*ech.Config, error) {
	if !o.Enable {
		return nil, nil
	}
	echConfig := &ech.Config{}
	if o.Config != "" {
		list, err := parseECHConfigList(o.Config)
		if err != nil {
			return nil, err
		}
		echConfig.GetEncryptedClientHelloConfigList = func(ctx context.Context, serverName string) ([]byte, error) {
			return list, nil
		}
		return echConfig, nil
	}

	var queryResolver resolver.Resolver // nil: the global proxy-server resolver
	if o.QueryServer != "" {
		var err error
		if queryResolver, err = newECHQueryResolver(o.QueryServer); err != nil {
			return nil, err
		}
	}
	echConfig.GetEncryptedClientHelloConfigList = func(ctx context.Context, serverName string) ([]byte, error) {
		if o.QueryServerName != "" { // overrides the domain name used for ECH HTTPS record queries
			serverName = o.QueryServerName
		}
		if queryResolver != nil {
			return queryResolver.ResolveECH(ctx, serverName)
		}
		return resolver.ResolveECHWithResolver(ctx, serverName, resolver.ProxyServerHostResolver)
	}
	return echConfig, nil
}

// parseECHConfigList accepts a base64 ECHConfigList or a PEM "ECH CONFIGS" block
// (as printed by xray tls ech --pem).
func parseECHConfigList(config string) ([]byte, error) {
	if strings.Contains(config, "-----BEGIN") {
		rest := []byte(config)
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				return nil, errors.New("no ECH CONFIGS block in the ech config pem")
			}
			if block.Type == "ECH CONFIGS" {
				return block.Bytes, nil
			}
		}
	}
	list, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(config), ""))
	if err != nil {
		return nil, fmt.Errorf("base64 decode ech config string failed: %v", err)
	}
	return list, nil
}

// newECHQueryResolver builds a dedicated resolver for the ECH HTTPS record
// queries of one proxy; it keeps its own cache, honoring the record TTL.
func newECHQueryResolver(server string) (resolver.Resolver, error) {
	// Xray's echConfigList "h2c://" DoH is "https://" with TLS added by the routing; we do TLS ourselves
	if rest, ok := strings.CutPrefix(server, "h2c://"); ok {
		server = "https://" + rest
	}
	if dns.ParseNameServer == nil {
		return nil, errors.New("ech-opts query-server: nameserver parser unavailable")
	}
	nss, err := dns.ParseNameServer([]string{server})
	if err != nil {
		return nil, fmt.Errorf("ech-opts query-server: %w", err)
	}
	if len(nss) == 0 {
		return nil, fmt.Errorf("ech-opts query-server: no nameserver in %q", server)
	}
	return dns.NewResolver(dns.Config{Main: nss, IPv6: true}).Resolver, nil
}
