package inbound_test

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Packet-up uploads sent with a method other than POST (uplink-http-method),
// with the data in the body, headers or cookies, as a client behind a CDN that
// passes only GET, or answers 405 to POST, sends them. The server leaves
// uplink-data-placement unset ("auto", as in Xray-core) or names it.
func TestInboundVless_XHTTP_PacketUpUplinkMethod(t *testing.T) {
	for _, method := range []string{"GET", "PUT", "POST"} {
		for _, placement := range []string{"body", "header", "cookie"} {
			for _, serverPlacement := range []string{"", placement} {
				method, placement, serverPlacement := method, placement, serverPlacement
				name := fmt.Sprintf("%s/%s/server=%s", method, placement, serverPlacement)
				if serverPlacement == "" {
					name = fmt.Sprintf("%s/%s/server=auto", method, placement)
				} else if placement == "body" {
					continue // the "" (auto) run covers the body
				}
				t.Run(name, func(t *testing.T) {
					inboundOptions := inbound.VlessOption{
						Certificate: tlsCertificate,
						PrivateKey:  tlsPrivateKey,
						XHTTPConfig: inbound.XHTTPConfig{
							Path:                "/vless-xhttp",
							Host:                "example.com",
							Mode:                "packet-up",
							UplinkDataPlacement: serverPlacement,
						},
					}
					outboundOptions := outbound.VlessOption{
						TLS:               true,
						Fingerprint:       tlsFingerprint,
						ServerName:        "example.org",
						ClientFingerprint: "chrome",
						Network:           "xhttp",
						XHTTPOpts: outbound.XHTTPOptions{
							Path:                "/vless-xhttp",
							Host:                "example.com",
							Mode:                "packet-up",
							UplinkHTTPMethod:    method,
							UplinkDataPlacement: placement,
						},
					}
					if placement != "body" {
						// the data rides in the request headers: keep each post small
						outboundOptions.XHTTPOpts.ScMaxEachPostBytes = "16384"
					}
					testInboundVless(t, inboundOptions, outboundOptions)
				})
			}
		}
	}
}

// GET uploads with the session and seq outside the path, and with
// x-padding-obfs-mode left at Xray-core's defaults.
func TestInboundVless_XHTTP_PacketUpGetMeta(t *testing.T) {
	for _, metaPlacement := range []string{"path", "query", "header", "cookie"} {
		for _, dataPlacement := range []string{"body", "header", "cookie"} {
			metaPlacement, dataPlacement := metaPlacement, dataPlacement
			t.Run(metaPlacement+"/"+dataPlacement, func(t *testing.T) {
				inboundOptions := inbound.VlessOption{
					Certificate: tlsCertificate,
					PrivateKey:  tlsPrivateKey,
					XHTTPConfig: inbound.XHTTPConfig{
						Path:             "/vless-xhttp",
						Host:             "example.com",
						Mode:             "packet-up",
						SessionPlacement: metaPlacement,
						SeqPlacement:     metaPlacement,
						XPaddingObfsMode: true,
					},
				}
				outboundOptions := outbound.VlessOption{
					TLS:               true,
					Fingerprint:       tlsFingerprint,
					ServerName:        "example.org",
					ClientFingerprint: "chrome",
					Network:           "xhttp",
					XHTTPOpts: outbound.XHTTPOptions{
						Path:                "/vless-xhttp",
						Host:                "example.com",
						Mode:                "packet-up",
						UplinkHTTPMethod:    "GET",
						UplinkDataPlacement: dataPlacement,
						SessionPlacement:    metaPlacement,
						SeqPlacement:        metaPlacement,
						XPaddingObfsMode:    true,
						ScMaxEachPostBytes:  "16384",
					},
				}
				testInboundVless(t, inboundOptions, outboundOptions)
			})
		}
	}
}

// server-max-header-bytes limits the request header size (Xray-core serverMaxHeaderBytes).
func TestInboundVless_XHTTP_ServerMaxHeaderBytes(t *testing.T) {
	testCases := []struct {
		name           string
		maxHeaderBytes int
		headerBytes    int
		wantTooLarge   bool
	}{
		{name: "default", maxHeaderBytes: 0, headerBytes: 64 * 1024, wantTooLarge: false},
		{name: "limited", maxHeaderBytes: 4096, headerBytes: 16 * 1024, wantTooLarge: true},
		{name: "raised", maxHeaderBytes: 128 * 1024, headerBytes: 64 * 1024, wantTooLarge: false},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			inboundOptions := inbound.VlessOption{
				BaseOption: inbound.BaseOption{
					NameStr: "vless_inbound",
					Listen:  "127.0.0.1",
					Port:    "0",
				},
				Users:         []inbound.VlessUser{{Username: "test", UUID: userUUID}},
				AllowInsecure: true,
				XHTTPConfig: inbound.XHTTPConfig{
					Path:                 "/vless-xhttp",
					Mode:                 "packet-up",
					ServerMaxHeaderBytes: testCase.maxHeaderBytes,
				},
			}
			in, err := inbound.NewVless(&inboundOptions)
			require.NoError(t, err)
			tunnel := NewHttpTestTunnel()
			defer tunnel.Close()
			require.NoError(t, in.Listen(tunnel))
			defer in.Close()

			conn, err := net.DialTimeout("tcp", in.Address(), 5*time.Second)
			require.NoError(t, err)
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

			request := "GET /vless-xhttp/session/0 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"X-Data-0: " + strings.Repeat("A", testCase.headerBytes) + "\r\n" +
				"Connection: close\r\n\r\n"
			_, err = conn.Write([]byte(request))
			require.NoError(t, err)

			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			require.NoError(t, err)
			_ = response.Body.Close()
			if testCase.wantTooLarge {
				assert.Equal(t, http.StatusRequestHeaderFieldsTooLarge, response.StatusCode)
			} else {
				// the headers got through; the request lacks x_padding, so it's a 400
				assert.Equal(t, http.StatusBadRequest, response.StatusCode)
			}
		})
	}
}

func TestInboundVless_XHTTP_ServerMaxHeaderBytesNegative(t *testing.T) {
	inboundOptions := inbound.VlessOption{
		BaseOption: inbound.BaseOption{
			NameStr: "vless_inbound",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Users:         []inbound.VlessUser{{Username: "test", UUID: userUUID}},
		AllowInsecure: true,
		XHTTPConfig: inbound.XHTTPConfig{
			Path:                 "/vless-xhttp",
			ServerMaxHeaderBytes: -1,
		},
	}
	in, err := inbound.NewVless(&inboundOptions)
	if err == nil {
		tunnel := NewHttpTestTunnel()
		defer tunnel.Close()
		err = in.Listen(tunnel)
		if err == nil {
			_ = in.Close()
		}
	}
	assert.ErrorContains(t, err, "server-max-header-bytes")
}
