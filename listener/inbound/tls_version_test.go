package inbound_test

import (
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/metacubex/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tlsTestInbound interface {
	Listen(tunnel C.Tunnel) error
	Address() string
	Close() error
}

var testBaseOption = inbound.BaseOption{Listen: "127.0.0.1", Port: "0"}

func tlsHandshake(address string, maxVersion uint16) (uint16, error) {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         maxVersion,
	})
	if err = tlsConn.Handshake(); err != nil {
		return 0, err
	}
	return tlsConn.ConnectionState().Version, nil
}

func TestInboundTLSMinVersion(t *testing.T) {
	cases := []struct {
		name string
		new  func() (tlsTestInbound, error)
	}{
		{"vless", func() (tlsTestInbound, error) {
			opts := inbound.VlessOption{
				BaseOption:  testBaseOption,
				Users:       []inbound.VlessUser{{Username: "test", UUID: userUUID}},
				Certificate: tlsCertificate,
				PrivateKey:  tlsPrivateKey,
			}
			opts.NameStr = "vless_tls_version"
			return inbound.NewVless(&opts)
		}},
		{"trojan", func() (tlsTestInbound, error) {
			opts := inbound.TrojanOption{
				BaseOption:  testBaseOption,
				Users:       []inbound.TrojanUser{{Username: "test", Password: userUUID}},
				Certificate: tlsCertificate,
				PrivateKey:  tlsPrivateKey,
			}
			opts.NameStr = "trojan_tls_version"
			return inbound.NewTrojan(&opts)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in, err := c.new()
			require.NoError(t, err)
			tunnel := NewHttpTestTunnel()
			defer tunnel.Close()
			require.NoError(t, in.Listen(tunnel))
			defer in.Close()

			_, err = tlsHandshake(in.Address(), tls.VersionTLS11)
			assert.Error(t, err, "TLS 1.1 handshake must be rejected")

			version, err := tlsHandshake(in.Address(), tls.VersionTLS12)
			if assert.NoError(t, err) {
				assert.Equal(t, uint16(tls.VersionTLS12), version)
			}
		})
	}
}
