package sing_vless

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

// xhttpALPN reads the alpn option of an xhttp inbound: whether it serves
// XHTTP over TCP (h2 and http/1.1, negotiated as before) and over HTTP/3.
// Unset keeps TCP only. As in Xray-core, `alpn: [h3]` serves HTTP/3 only;
// h3 together with h2 or http/1.1 serves both, TCP and UDP on the same port.
func xhttpALPN(alpn []string, xhttpOn bool) (tcp, h3 bool, err error) {
	if len(alpn) == 0 {
		return true, false, nil
	}
	if !xhttpOn {
		return false, false, errors.New("alpn is only supported with xhttp-config")
	}
	for _, proto := range alpn {
		switch proto {
		case http3.NextProtoH3:
			h3 = true
		case "h2", "http/1.1":
			tcp = true
		default:
			return false, false, fmt.Errorf("unsupported alpn %q: xhttp serves h3, h2 and http/1.1", proto)
		}
	}
	return tcp, h3, nil
}

// h3SecurityError explains why the security modes do not allow HTTP/3, or
// returns nil. QUIC runs its own TLS 1.3 handshake, so only a plain
// certificate fits: REALITY, ShadowTLS, ResTLS and JLS all work on the TLS
// records of a TCP stream.
func h3SecurityError(securityModes []string) error {
	if len(securityModes) == 0 {
		return errors.New("xhttp over h3 requires certificate and private-key")
	}
	if securityModes[0] != "certificate" {
		return fmt.Errorf("xhttp over h3 cannot be combined with %s: QUIC carries its own TLS handshake, use certificate and private-key", securityModes[0])
	}
	return nil
}

// h3UDPAddr is the UDP address for the HTTP/3 server of addr: the port of
// the TCP listener when both run and addr asks for any port (0), so that
// TCP and UDP share it as they do with a fixed port.
func h3UDPAddr(addr string, tcp net.Addr) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port != "0" || tcp == nil {
		return addr
	}
	if tcpAddr, ok := tcp.(*net.TCPAddr); ok {
		return net.JoinHostPort(host, strconv.Itoa(tcpAddr.Port))
	}
	return addr
}

// h3MaxIncomingStreams bounds the concurrent request streams of one QUIC
// connection. Every stream-one or stream-up tunnel holds one or two streams
// and every packet-up upload one more while it is sent; streams over the
// limit are not refused, QUIC flow control (MAX_STREAMS) makes the client
// wait. The Go HTTP/2 server allows 250 per TCP connection.
const h3MaxIncomingStreams = 1024

// h3KeepAlivePeriod makes the server ping a quiet connection, so an idle
// tunnel survives a client that does not ping (the Citrus client pings every
// 10s). A vanished client answers nothing and is dropped by the idle timeout,
// which QUIC counts from the last packet received.
const h3KeepAlivePeriod = 10 * time.Second

const h3MaxIdleTimeout = 30 * time.Second

// h3ShutdownTimeout is how long Close waits after the GOAWAY for requests in
// flight (packet-up uploads) before it closes the connections. Long-lived
// downloads never finish on their own; their clients see the connection
// closed and dial again. A variable only so that tests can shorten it.
var h3ShutdownTimeout = time.Second

func h3QUICConfig() *quic.Config {
	return &quic.Config{
		Versions:           []quic.Version{quic.Version1},
		MaxIdleTimeout:     h3MaxIdleTimeout,
		KeepAlivePeriod:    h3KeepAlivePeriod,
		MaxIncomingStreams: h3MaxIncomingStreams,
		// as in Xray-core: path MTU discovery only where quic-go implements it
		DisablePathMTUDiscovery: !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		// 0-RTT data could be replayed, and the first request of a tunnel
		// carries the VLESS header
		Allow0RTT: false,
	}
}

// h3Listener is the HTTP/3 server of one listen address.
type h3Listener struct {
	server   *http3.Server
	listener *quic.EarlyListener
	conn     net.PacketConn
}

// listenH3 serves handler over HTTP/3 on conn, which it then owns.
func listenH3(conn net.PacketConn, tlsConfig *tls.Config, handler http.Handler, maxHeaderBytes int) (*h3Listener, error) {
	ln, err := quic.ListenEarly(conn, http3.ConfigureTLSConfig(tlsConfig), h3QUICConfig())
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	server := &http3.Server{
		Handler: handler,
		// the TCP server's IdleTimeout: a connection without requests
		IdleTimeout:    30 * time.Second,
		MaxHeaderBytes: maxHeaderBytes,
	}
	go func() {
		if err := server.ServeListener(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warnln("[VLESS] HTTP/3 server on %s stopped: %s", conn.LocalAddr(), err)
		}
	}()
	return &h3Listener{server: server, listener: ln, conn: conn}, nil
}

// Close sends GOAWAY, gives the requests in flight h3ShutdownTimeout and then
// closes the connections with H3_NO_ERROR, so clients learn at once instead
// of after their idle timeout. The UDP socket is closed before Close returns,
// so a reloaded listener can bind the port again.
func (l *h3Listener) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), h3ShutdownTimeout)
	err := l.server.Shutdown(ctx)
	cancel()
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	if cErr := l.listener.Close(); cErr != nil && !errors.Is(cErr, quic.ErrServerClosed) && err == nil {
		err = cErr
	}
	if cErr := l.conn.Close(); cErr != nil && err == nil {
		err = cErr
	}
	return err
}
