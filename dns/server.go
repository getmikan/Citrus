package dns

import (
	"context"
	"net"
	"time"

	"github.com/metacubex/mihomo/common/sockopt"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

const (
	// maxInflightQueries caps the queries the listener resolves at once.
	// A flood of unique names fans out to every upstream, so beyond this cap
	// new queries are shed instead of piling up goroutines and sockets.
	maxInflightQueries = 1024

	// TCP connection limits of the listener. These match the miekg/dns
	// defaults, set explicitly so a library change cannot drop them.
	tcpReadTimeout  = 2 * time.Second
	tcpWriteTimeout = 2 * time.Second
	tcpIdleTimeout  = 8 * time.Second
	tcpMaxQueries   = 128
)

// queryTimeout bounds the whole resolution of one listener query, fallback
// and retries included: twice the timeout of a single upstream exchange.
var queryTimeout = 2 * resolver.DefaultDNSTimeout

var (
	address string
	server  = newServer(nil)

	dnsDefaultTTL uint32 = 600
)

type Server struct {
	service   resolver.Service
	tcpServer *D.Server
	udpServer *D.Server

	inflight     chan struct{} // semaphore, one slot per query in progress
	queryTimeout time.Duration
}

func newServer(service resolver.Service) *Server {
	return &Server{
		service:      service,
		inflight:     make(chan struct{}, maxInflightQueries),
		queryTimeout: queryTimeout,
	}
}

type serverHandler struct {
	*Server
	isUDP bool
}

// ServeDNS implement D.Handler ServeDNS
func (s serverHandler) ServeDNS(w D.ResponseWriter, r *D.Msg) {
	// never wait for a slot: miekg/dns serves each UDP packet in its own
	// goroutine and each TCP connection serially, so waiting here would only
	// stack goroutines up (UDP) or stall the connection (TCP)
	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		if s.isUDP {
			// Drop: the client retries on its own timer, a SERVFAIL to an
			// unverified (possibly spoofed) source would make the overloaded
			// listener a reflector, and stub resolvers may cache SERVFAIL
			// (RFC 2308 section 7.1) past the moment of overload.
			return
		}
		// TCP: the peer completed a handshake and waits on this connection,
		// so answer right away instead of holding it until the read timeout
		writeServerFailure(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.queryTimeout)
	defer cancel()

	msg, err := s.service.ServeMsg(ctx, r)
	if err != nil {
		writeServerFailure(w, r)
		return
	}
	if s.isUDP {
		// RFC 6891: fit the reply into the client's advertised buffer size,
		// setting the TC bit if records must be dropped; 512 when no OPT present
		msg.Truncate(resolver.RequestUDPSize(r))
	}
	msg.Compress = true
	w.WriteMsg(msg)
}

func writeServerFailure(w D.ResponseWriter, r *D.Msg) {
	m := new(D.Msg)
	m.SetRcode(r, D.RcodeServerFailure)
	// does not matter if this write fails
	_ = w.WriteMsg(m)
}

func (s *Server) UDPHandler() D.Handler {
	return serverHandler{Server: s, isUDP: true}
}

func (s *Server) TCPHandler() D.Handler {
	return serverHandler{Server: s, isUDP: false}
}

func (s *Server) SetService(service resolver.Service) {
	s.service = service
}

func ReCreateServer(addr string, lc C.InboundListenConfig, service resolver.Service) {
	if addr == address && service != nil {
		server.SetService(service)
		return
	}

	if server.tcpServer != nil {
		_ = server.tcpServer.Shutdown()
		server.tcpServer = nil
	}

	if server.udpServer != nil {
		_ = server.udpServer.Shutdown()
		server.udpServer = nil
	}

	server.service = nil
	address = ""

	if addr == "" || lc == nil || service == nil {
		return
	}

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start DNS server error: %s", err.Error())
		}
	}()

	_, port, err := net.SplitHostPort(addr)
	if port == "0" || port == "" || err != nil {
		return
	}

	address = addr
	server = newServer(service)

	go func() {
		p, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			log.Errorln("Start DNS server(UDP) error: %s", err.Error())
			return
		}

		if err := sockopt.UDPReuseaddr(p); err != nil {
			log.Warnln("Failed to Reuse UDP Address: %s", err)
		}

		log.Infoln("DNS server(UDP) listening at: %s", p.LocalAddr().String())
		server.udpServer = &D.Server{Addr: addr, PacketConn: p, Handler: server.UDPHandler()}
		_ = server.udpServer.ActivateAndServe()
	}()

	go func() {
		l, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			log.Errorln("Start DNS server(TCP) error: %s", err.Error())
			return
		}

		log.Infoln("DNS server(TCP) listening at: %s", l.Addr().String())
		server.tcpServer = &D.Server{
			Addr:          addr,
			Listener:      l,
			Handler:       server.TCPHandler(),
			ReadTimeout:   tcpReadTimeout,
			WriteTimeout:  tcpWriteTimeout,
			IdleTimeout:   func() time.Duration { return tcpIdleTimeout },
			MaxTCPQueries: tcpMaxQueries,
		}
		_ = server.tcpServer.ActivateAndServe()
	}()

}
