package trusttunnel

import (
	"context"
	"errors"
	"net"
	"runtime"

	"github.com/metacubex/mihomo/transport/tuic/common"
	"github.com/metacubex/mihomo/transport/v2ray"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

func (c *Client) quicRoundTripper(tlsConfig *v2ray.TLSConfig, congestionControlName string, cwnd int, bbrProfile string) error {
	stdConfig, err := tlsConfig.ToStdConfig()
	if err != nil {
		return err
	}
	c.roundTripper = &http3.Transport{
		TLSClientConfig: stdConfig,
		QUICConfig: &quic.Config{
			Versions:                   []quic.Version{quic.Version1},
			MaxIdleTimeout:             DefaultQuicMaxIdleTimeout,
			InitialStreamReceiveWindow: DefaultQuicStreamReceiveWindow,
			DisablePathMTUDiscovery:    !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
			Allow0RTT:                  false,
		},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			err := tlsConfig.ECH.ClientHandle(ctx, tlsCfg)
			if err != nil {
				return nil, err
			}
			_, quicConn, err := common.DialQuic(ctx, addr, c.dialOptions(), c.dialer, tlsCfg, cfg, common.DialQuicOption{Early: true})
			if err != nil {
				return nil, err
			}
			common.SetCongestionController(quicConn, congestionControlName, cwnd, bbrProfile)
			return quicConn, nil
		},
	}
	return nil
}

// serverMaxIncomingStreams bounds the concurrent HTTP/3 request streams of
// one connection. Every CONNECT is one request stream, and streams are
// opened before Proxy-Authorization is checked. Streams over the limit are
// not refused: QUIC flow control (MAX_STREAMS) makes the client wait (the
// HTTP/3 transport opens streams with OpenStreamSync). The client pools up
// to 8 connections, and over HTTP/2 a connection already gets 250 concurrent
// streams (the Go HTTP/2 server default), so 1024 is generous.
const serverMaxIncomingStreams = 1024

func serverQUICConfig(zeroRTT bool) *quic.Config {
	return &quic.Config{
		Versions:           []quic.Version{quic.Version1},
		MaxIdleTimeout:     DefaultQuicMaxIdleTimeout,
		KeepAlivePeriod:    quicKeepAlivePeriod,
		MaxIncomingStreams: serverMaxIncomingStreams,
		Allow0RTT:          zeroRTT,
	}
}

func (s *Service) configHTTP3Server(tlsConfig *tls.Config, udpConn net.PacketConn) error {
	tlsConfig = http3.ConfigureTLSConfig(tlsConfig)
	quicListener, err := quic.ListenEarly(udpConn, tlsConfig, serverQUICConfig(s.quicZeroRTT))
	if err != nil {
		return err
	}
	h3Server := &http3.Server{
		Handler:     s,
		IdleTimeout: DefaultSessionTimeout,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			common.SetCongestionController(conn, s.quicCongestionControl, s.quicCwnd, s.quicBBRProfile)
			return ctx
		},
	}
	s.h3Server = h3Server
	s.udpConn = udpConn
	go func() {
		sErr := h3Server.ServeListener(quicListener)
		if sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
			s.logger.ErrorContext(s.ctx, "HTTP3 server close: ", sErr)
		}
	}()
	return nil
}
