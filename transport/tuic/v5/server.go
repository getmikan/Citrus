package v5

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"sync"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/atomic"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/authevent"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbounduser"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/tuic/types"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
)

type ServerOption struct {
	HandleTcpFn func(conn net.Conn, addr socks5.Addr, additions ...inbound.Addition) error
	HandleUdpFn func(addr socks5.Addr, packet C.UDPPacket, additions ...inbound.Addition) error

	Users                 *inbounduser.Set[[16]byte] // Name = uuid, Secret = password
	MaxUdpRelayPacketSize int
}

func NewServerHandler(option *ServerOption, quicConn *quic.Conn, uuid uuid.UUID) types.ServerHandler {
	return &serverHandler{
		ServerOption: option,
		quicConn:     quicConn,
		uuid:         uuid,
		authCh:       make(chan struct{}),
		fragCache:    fragCache[uint32]{maxPackets: serverMaxFragPackets},
	}
}

type serverHandler struct {
	*ServerOption
	quicConn *quic.Conn
	uuid     uuid.UUID

	authCh   chan struct{}
	authOk   atomic.Bool
	authUUID atomic.TypedValue[string]
	authOnce sync.Once

	udpInputMap xsync.Map[uint16, *serverUDPInput]
	// fragCache reassembles fragmented packets of every association of the
	// connection, keyed by ASSOC_ID<<16 | PKT_ID, so the connection has one
	// bounded budget of incomplete packets however many associations it opens.
	fragCache fragCache[uint32]
}

func (s *serverHandler) AuthOk() bool {
	return s.authOk.Load()
}

// AuthDone is closed once authentication succeeded, failed or timed out.
func (s *serverHandler) AuthDone() <-chan struct{} {
	return s.authCh
}

func (s *serverHandler) HandleTimeout() {
	s.authOnce.Do(func() {
		authevent.EmitAddr("tuic", authevent.ReasonAuthenticationTimeout, s.quicConn.LocalAddr(), s.quicConn.RemoteAddr())
		_ = s.quicConn.CloseWithError(AuthenticationTimeout, "AuthenticationTimeout")
		s.authOk.Store(false)
		close(s.authCh)
	})
}

func (s *serverHandler) HandleMessage(message []byte) (err error) {
	reader := bytes.NewBuffer(message)
	commandHead, err := ReadCommandHead(reader)
	if err != nil {
		return
	}
	switch commandHead.TYPE {
	case PacketType:
		var packet Packet
		packet, err = ReadPacketWithHead(commandHead, reader)
		if err != nil {
			return
		}
		return s.parsePacket(&packet, types.NATIVE)
	case HeartbeatType:
		var heartbeat Heartbeat
		heartbeat, err = ReadHeartbeatWithHead(commandHead, reader)
		if err != nil {
			return
		}
		heartbeat.BytesLen()
	}
	return
}

func (s *serverHandler) parsePacket(packet *Packet, udpRelayMode types.UdpRelayMode) (err error) {
	<-s.authCh
	if !s.authOk.Load() {
		return
	}
	var assocId uint16

	assocId = packet.ASSOC_ID

	input, _ := s.udpInputMap.LoadOrStoreFn(assocId, func() *serverUDPInput { return &serverUDPInput{} })
	if input.writeClosed.Load() {
		return nil
	}
	packetPtr := s.fragCache.feed(uint32(assocId)<<16|uint32(packet.PKT_ID), packet)
	if packetPtr == nil {
		return
	}

	pc := &quicStreamPacketConn{
		connId:                assocId,
		quicConn:              s.quicConn,
		inputConn:             nil,
		udpRelayMode:          udpRelayMode,
		maxUdpRelayPacketSize: s.MaxUdpRelayPacketSize,
		deferQuicConnFn:       nil,
		closeDeferFn:          nil,
		writeClosed:           &input.writeClosed,
	}

	return s.HandleUdpFn(packetPtr.ADDR.SocksAddr(), &serverUDPPacket{
		pc:     pc,
		packet: packetPtr,
		rAddr:  N.NewCustomAddr("tuic", fmt.Sprintf("tuic-%s-%d", s.uuid, assocId), s.quicConn.RemoteAddr()), // for tunnel's handleUDPConn
	}, inbound.WithInUser(s.authUUID.Load()))
}

func (s *serverHandler) HandleStream(conn *N.BufferedConn) (err error) {
	connect, err := ReadConnect(conn)
	if err != nil {
		_ = conn.Close()
		return err
	}
	<-s.authCh
	if !s.authOk.Load() {
		return conn.Close()
	}

	err = s.HandleTcpFn(conn, connect.ADDR.SocksAddr(), inbound.WithInUser(s.authUUID.Load()))
	if err != nil {
		_ = conn.Close()
		return err
	}
	return
}

func (s *serverHandler) HandleUniStream(reader *bufio.Reader) (err error) {
	commandHead, err := ReadCommandHead(reader)
	if err != nil {
		return
	}
	switch commandHead.TYPE {
	case AuthenticateType:
		var authenticate Authenticate
		authenticate, err = ReadAuthenticateWithHead(commandHead, reader)
		if err != nil {
			return
		}
		authOk := false
		var authUUID uuid.UUID
		var token [32]byte
		if entry, ok := s.Users.Lookup(authenticate.UUID); ok {
			token, err = GenToken(s.quicConn.ConnectionState(), authenticate.UUID, entry.Secret())
			if err != nil {
				return
			}
			if token == authenticate.TOKEN {
				// the connection dies with the user: removing or re-keying
				// it closes the QUIC connection
				release, bound := s.Users.Bind(entry, quicCloser{s.quicConn})
				if bound {
					authOk = true
					authUUID = authenticate.UUID
					go func() {
						<-s.quicConn.Context().Done()
						release()
					}()
				}
			}
		}
		s.authOnce.Do(func() {
			if !authOk {
				authevent.EmitAddr("tuic", authevent.ReasonWrongCredentials, s.quicConn.LocalAddr(), s.quicConn.RemoteAddr())
				_ = s.quicConn.CloseWithError(AuthenticationFailed, "AuthenticationFailed")
			}
			s.authOk.Store(authOk)
			s.authUUID.Store(authUUID.String())
			close(s.authCh)
		})
	case PacketType:
		var packet Packet
		packet, err = ReadPacketWithHead(commandHead, reader)
		if err != nil {
			return
		}
		return s.parsePacket(&packet, types.QUIC)
	case DissociateType:
		var disassociate Dissociate
		disassociate, err = ReadDissociateWithHead(commandHead, reader)
		if err != nil {
			return
		}
		if input, loaded := s.udpInputMap.LoadAndDelete(disassociate.ASSOC_ID); loaded {
			input.writeClosed.Store(true)
		}
	}
	return
}

type quicCloser struct{ conn *quic.Conn }

func (c quicCloser) Close() error {
	return c.conn.CloseWithError(AuthenticationFailed, "user removed")
}

// UserKey maps a user to its TUIC v5 UUID (the name).
func UserKey(user C.InboundUser) ([16]byte, error) {
	id, err := uuid.FromString(user.Name)
	if err != nil {
		return [16]byte{}, fmt.Errorf("%w: user %q: name must be a UUID", C.ErrInvalidInboundUser, user.Name)
	}
	return id, nil
}

type serverUDPInput struct {
	writeClosed atomic.Bool
}

type serverUDPPacket struct {
	pc     *quicStreamPacketConn
	packet *Packet
	rAddr  net.Addr
}

func (s *serverUDPPacket) InAddr() net.Addr {
	return s.pc.LocalAddr()
}

func (s *serverUDPPacket) LocalAddr() net.Addr {
	return s.rAddr
}

func (s *serverUDPPacket) Data() []byte {
	return s.packet.DATA
}

func (s *serverUDPPacket) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	return s.pc.WriteTo(b, addr)
}

func (s *serverUDPPacket) Drop() {
	s.packet.DATA = nil
}

var _ C.UDPPacket = (*serverUDPPacket)(nil)
var _ C.UDPPacketInAddr = (*serverUDPPacket)(nil)
