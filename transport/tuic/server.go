package tuic

import (
	"bufio"
	"context"
	"net"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbounduser"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/tuic/common"
	"github.com/metacubex/mihomo/transport/tuic/types"
	v5 "github.com/metacubex/mihomo/transport/tuic/v5"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

// Before a connection has authenticated, every stream or datagram handler
// would park on the authentication outcome (up to AuthenticationTimeout plus
// the handshake). These budgets bound how many such handlers a connection may
// have at once; after authentication they no longer apply.
//
//   - streams (bidirectional, TCP relay): the accept loop waits for a free
//     slot, so extra streams stay queued in QUIC (still bounded by
//     MaxIncomingStreams) and are served as soon as the auth arrives;
//   - unidirectional streams carrying a packet (UDP-over-stream): dropped when
//     the budget is full, as UDP may be. The accept loop itself never waits:
//     the client opens the authenticate stream concurrently with its first
//     packets, so it may come after them. The other commands (authenticate,
//     dissociate, heartbeat) do not wait for the outcome;
//   - datagrams (native UDP relay): dropped when the budget is full.
const (
	preAuthMaxStreams    = 64
	preAuthMaxUniStreams = 64
	preAuthMaxDatagrams  = 64
)

// streamHeaderBufferSize is the read buffer of a TCP relay stream.
const streamHeaderBufferSize = 512

type ServerOption struct {
	HandleTcpFn func(conn net.Conn, addr socks5.Addr, additions ...inbound.Addition) error
	HandleUdpFn func(addr socks5.Addr, packet C.UDPPacket, additions ...inbound.Addition) error

	TlsConfig             *tls.Config
	QuicConfig            *quic.Config
	Users                 *inbounduser.Set[[16]byte] // V5 special: Name = uuid, Secret = password
	CongestionController  string
	AuthenticationTimeout time.Duration
	MaxUdpRelayPacketSize int
	CWND                  int
	BBRProfile            string
}

type Server struct {
	*ServerOption
	optionV5 *v5.ServerOption
	listener *quic.EarlyListener
}

func (s *Server) Serve() error {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return err
		}
		common.SetCongestionController(conn, s.CongestionController, s.CWND, s.BBRProfile)
		h := &serverHandler{
			Server:   s,
			quicConn: conn,
			uuid:     utils.NewUUIDV4(),
		}
		if h.optionV5 != nil {
			h.v5Handler = v5.NewServerHandler(h.optionV5, conn, h.uuid)
		}
		h.streamSlots = make(chan struct{}, preAuthMaxStreams)
		h.uniStreamSlots = make(chan struct{}, preAuthMaxUniStreams)
		h.datagramSlots = make(chan struct{}, preAuthMaxDatagrams)
		go h.handle()
	}
}

func (s *Server) Close() error {
	return s.listener.Close()
}

type serverHandler struct {
	*Server
	quicConn *quic.Conn
	uuid     uuid.UUID

	v5Handler types.ServerHandler

	// pre-authentication budgets, see preAuthMaxStreams
	streamSlots    chan struct{}
	uniStreamSlots chan struct{}
	datagramSlots  chan struct{}
}

func releaseNothing() {}

// preAuthSlot takes a slot of the pre-authentication budget for one handler.
// Once the authentication outcome is known no slot is needed. With wait it
// blocks until a slot frees up, the outcome is known or the connection is
// gone; without wait it gives up at once. ok is false when the input must be
// dropped.
func (s *serverHandler) preAuthSlot(slots chan struct{}, wait bool) (release func(), ok bool) {
	if s.v5Handler == nil {
		return releaseNothing, true
	}
	authDone := s.v5Handler.AuthDone()
	select {
	case <-authDone:
		return releaseNothing, true
	default:
	}
	release = func() { <-slots }
	if !wait {
		select {
		case slots <- struct{}{}:
			return release, true
		case <-authDone:
			return releaseNothing, true
		default:
			return nil, false
		}
	}
	select {
	case slots <- struct{}{}:
		return release, true
	case <-authDone:
		return releaseNothing, true
	case <-s.quicConn.Context().Done():
		return nil, false
	}
}

func (s *serverHandler) handle() {
	go func() {
		_ = s.handleUniStream()
	}()
	go func() {
		_ = s.handleStream()
	}()
	go func() {
		_ = s.handleMessage()
	}()

	select {
	case <-s.quicConn.HandshakeComplete(): // this chan maybe not closed if handshake never complete
	case <-time.After(s.quicConn.Config().HandshakeIdleTimeout): // HandshakeIdleTimeout in real conn.Config() never be zero
	}

	time.AfterFunc(s.AuthenticationTimeout, func() {
		if s.v5Handler != nil {
			if s.v5Handler.AuthOk() {
				return
			}
		}

		if s.v5Handler != nil {
			s.v5Handler.HandleTimeout()
		}
	})
}

func (s *serverHandler) handleMessage() (err error) {
	for {
		var message []byte
		message, err = s.quicConn.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		release, ok := s.preAuthSlot(s.datagramSlots, false)
		if !ok {
			continue
		}
		go func() (err error) {
			defer release()
			if len(message) > 0 {
				switch message[0] {
				case v5.VER:
					if s.v5Handler != nil {
						return s.v5Handler.HandleMessage(message)
					}
				}
			}
			return
		}()
	}
}

func (s *serverHandler) handleStream() (err error) {
	for {
		var quicStream *quic.Stream
		quicStream, err = s.quicConn.AcceptStream(context.Background())
		if err != nil {
			return err
		}
		release, ok := s.preAuthSlot(s.streamSlots, true)
		if !ok {
			quicStream.CancelRead(0)
			quicStream.CancelWrite(0)
			return context.Cause(s.quicConn.Context())
		}
		go func() (err error) {
			defer release()
			stream := types.NewQuicStreamConn(
				quicStream,
				s.quicConn.LocalAddr(),
				s.quicConn.RemoteAddr(),
				nil,
			)
			// the reader only has to hold the version and the CONNECT
			// command (an address of at most 2+255+2 bytes); what it reads
			// past them is relayed from it and the reader is dropped
			conn := N.NewBufferedConnSize(stream, streamHeaderBufferSize)

			verBytes, err := conn.Peek(1)
			if err != nil {
				_ = conn.Close()
				return err
			}

			switch verBytes[0] {
			case v5.VER:
				if s.v5Handler != nil {
					return s.v5Handler.HandleStream(conn)
				}
			}
			_ = conn.Close()
			return
		}()
	}
}

func (s *serverHandler) handleUniStream() (err error) {
	for {
		var stream *quic.ReceiveStream
		stream, err = s.quicConn.AcceptUniStream(context.Background())
		if err != nil {
			return err
		}
		go func() (err error) {
			defer func() {
				stream.CancelRead(0)
			}()
			reader := bufio.NewReader(stream)
			head, err := reader.Peek(2) // VER, TYPE
			if err != nil {
				return err
			}

			switch head[0] {
			case v5.VER:
				if s.v5Handler != nil {
					if v5.CommandType(head[1]) == v5.PacketType {
						// a packet parks until the authentication outcome is known
						release, ok := s.preAuthSlot(s.uniStreamSlots, false)
						if !ok {
							return
						}
						defer release()
					}
					return s.v5Handler.HandleUniStream(reader)
				}
			}
			return
		}()
	}
}

func NewServer(option *ServerOption, pc net.PacketConn) (*Server, error) {
	listener, err := quic.ListenEarly(pc, option.TlsConfig, option.QuicConfig)
	if err != nil {
		return nil, err
	}
	server := &Server{
		ServerOption: option,
		listener:     listener,
	}
	if option.Users != nil {
		maxUdpRelayPacketSize := option.MaxUdpRelayPacketSize
		if maxUdpRelayPacketSize > MaxFragSizeV5 {
			maxUdpRelayPacketSize = MaxFragSizeV5
		}
		server.optionV5 = &v5.ServerOption{
			HandleTcpFn:           option.HandleTcpFn,
			HandleUdpFn:           option.HandleUdpFn,
			Users:                 option.Users,
			MaxUdpRelayPacketSize: maxUdpRelayPacketSize,
		}
	}
	return server, nil
}
