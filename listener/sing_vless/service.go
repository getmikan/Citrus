package sing_vless

// copy and modify from https://github.com/SagerNet/sing-vmess/tree/3c1cf255413250b09a57e4ecdf1def1fa505e3cc/vless

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/authevent"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbounduser"
	"github.com/metacubex/mihomo/transport/vless"
	"github.com/metacubex/mihomo/transport/vless/vision"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/sing-vmess"
	"github.com/metacubex/sing/common/auth"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"google.golang.org/protobuf/proto"
)

type Service struct {
	users   *inbounduser.Set[[16]byte]
	handler Handler
}

type Handler interface {
	N.TCPConnectionHandler
	N.UDPConnectionHandler
	E.Handler
}

// userKey maps a user to its VLESS id: the UUID, or the UUIDv5 of any other
// string (the Xray convention).
func userKey(user C.InboundUser) ([16]byte, error) {
	return utils.UUIDMap(user.Secret), nil
}

// NewService returns a service for users (Name = username, Secret = uuid,
// Flow = flow).
func NewService(handler Handler, users []C.InboundUser) *Service {
	set, _ := inbounduser.New(userKey, users) // userKey never fails
	return &Service{handler: handler, users: set}
}

// Users returns the current users.
func (s *Service) Users() []C.InboundUser { return s.users.Users() }

// ReplaceUsers swaps the users in place; the sessions of the removed and
// changed users are closed.
func (s *Service) ReplaceUsers(users []C.InboundUser) (inbounduser.Change, error) {
	for _, user := range users {
		if user.Flow != "" && user.Flow != vless.XRV {
			return inbounduser.Change{}, fmt.Errorf("%w: user %q: unknown flow %q", C.ErrInvalidInboundUser, user.Name, user.Flow)
		}
	}
	return s.users.Replace(users)
}

var _ N.TCPConnectionHandler = (*Service)(nil)

func (s *Service) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	var version uint8
	err := binary.Read(conn, binary.BigEndian, &version)
	if err != nil {
		return err
	}
	if version != vless.Version {
		return E.New("unknown version: ", version)
	}

	var requestUUID [16]byte
	_, err = io.ReadFull(conn, requestUUID[:])
	if err != nil {
		return err
	}

	var addonsLen uint8
	err = binary.Read(conn, binary.BigEndian, &addonsLen)
	if err != nil {
		return err
	}

	var addons vless.Addons
	if addonsLen > 0 {
		addonsBytes := make([]byte, addonsLen)
		_, err = io.ReadFull(conn, addonsBytes)
		if err != nil {
			return err
		}

		err = proto.Unmarshal(addonsBytes, &addons)
		if err != nil {
			return err
		}
	}

	var command byte
	err = binary.Read(conn, binary.BigEndian, &command)
	if err != nil {
		return err
	}

	var destination M.Socksaddr
	if command != vless.CommandMux {
		destination, err = vmess.AddressSerializer.ReadAddrPort(conn)
		if err != nil {
			return err
		}
	}

	entry, loaded := s.users.Lookup(requestUUID)
	if !loaded {
		authevent.EmitAddr("vless", authevent.ReasonWrongCredentials, conn.LocalAddr(), clientAddr(ctx, conn))
		return E.New("unknown UUID: ", uuid.FromBytesOrNil(requestUUID[:]))
	}
	ctx = auth.ContextWithUser(ctx, entry.Name())
	metadata.Destination = destination

	userFlow := entry.Flow()
	requestFlow := addons.Flow
	if requestFlow != userFlow && requestFlow != "" {
		return E.New("flow mismatch: expected ", flowName(userFlow), ", but got ", flowName(requestFlow))
	}
	// the header is read and the user is authenticated: lift the handshake
	// deadline set by the listener, the session may idle from here on
	clearHandshakeDeadline(conn)
	if onAuthenticated := onAuthenticatedFrom(ctx); onAuthenticated != nil {
		onAuthenticated() // e.g. an xhttp session leaves its pre-auth limits
	}

	// the session dies with the user: removing or re-keying it closes conn
	release, ok := s.users.Bind(entry, conn)
	if !ok {
		return E.New("user ", entry.Name(), " was removed")
	}
	defer release()

	responseConn := &serverConn{ExtendedConn: bufio.NewExtendedConn(conn)}
	switch requestFlow {
	case vless.XRV:
		conn, err = vision.NewConn(responseConn, conn, requestUUID)
		if err != nil {
			return E.Cause(err, "initialize vision")
		}
	case "":
		conn = responseConn
	default:
		return E.New("unknown flow: ", requestFlow)
	}
	switch command {
	case vless.CommandTCP:
		return s.handler.NewConnection(ctx, conn, metadata)
	case vless.CommandUDP:
		if requestFlow == vless.XRV {
			return E.New(vless.XRV, " flow does not support UDP")
		}
		return s.handler.NewPacketConnection(ctx, &serverPacketConn{ExtendedConn: bufio.NewExtendedConn(conn), destination: destination}, metadata)
	case vless.CommandMux:
		// sing-vmess uses both a buffered writer and direct WriteBuffer calls.
		// Serialize them before the lazy VLESS response and encryption layer:
		// concurrent streams must not interleave encryption records or headers.
		return vmess.HandleMuxConnection(ctx, &muxWriteConn{Conn: conn}, metadata, s.handler)
	default:
		return E.New("unknown command: ", command)
	}
}

type clientAddrKey struct{}

// withClientAddr records the address of the client behind a trusted reverse
// proxy, for the auth events of the connection.
func withClientAddr(ctx context.Context, addr net.Addr) context.Context {
	return context.WithValue(ctx, clientAddrKey{}, addr)
}

func clientAddr(ctx context.Context, conn net.Conn) net.Addr {
	if addr, ok := ctx.Value(clientAddrKey{}).(net.Addr); ok {
		return addr
	}
	return conn.RemoteAddr()
}

func flowName(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

type serverConn struct {
	N.ExtendedConn
	responseWritten bool
}

func (c *serverConn) Write(b []byte) (n int, err error) {
	if !c.responseWritten {
		buffer := buf.NewSize(2 + len(b))
		buffer.WriteByte(vless.Version)
		buffer.WriteByte(0)
		buffer.Write(b)
		_, err = c.ExtendedConn.Write(buffer.Bytes())
		buffer.Release()
		if err == nil {
			n = len(b)
		}
		c.responseWritten = true
		return
	}
	return c.ExtendedConn.Write(b)
}

func (c *serverConn) WriteBuffer(buffer *buf.Buffer) error {
	if !c.responseWritten {
		header := buffer.ExtendHeader(2)
		header[0] = vless.Version
		header[1] = 0
		c.responseWritten = true
	}
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *serverConn) FrontHeadroom() int {
	if c.responseWritten {
		return 0
	}
	return 2
}

func (c *serverConn) ReaderReplaceable() bool {
	return true
}

func (c *serverConn) WriterReplaceable() bool {
	return c.responseWritten
}

func (c *serverConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *serverConn) Upstream() any {
	return c.ExtendedConn
}

type serverPacketConn struct {
	N.ExtendedConn
	destination     M.Socksaddr
	readWaitOptions N.ReadWaitOptions
}

func (c *serverPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions = options
	return false
}

func (c *serverPacketConn) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	var packetLen uint16
	err = binary.Read(c.ExtendedConn, binary.BigEndian, &packetLen)
	if err != nil {
		return
	}

	buffer = c.readWaitOptions.NewPacketBuffer()
	_, err = buffer.ReadFullFrom(c.ExtendedConn, int(packetLen))
	if err != nil {
		buffer.Release()
		return
	}
	c.readWaitOptions.PostReturn(buffer)

	destination = c.destination
	return
}

func (c *serverPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var packetLen uint16
	err = binary.Read(c.ExtendedConn, binary.BigEndian, &packetLen)
	if err != nil {
		return
	}
	if len(p) < int(packetLen) {
		err = io.ErrShortBuffer
		return
	}
	n, err = io.ReadFull(c.ExtendedConn, p[:packetLen])
	if err != nil {
		return
	}
	if c.destination.IsFqdn() {
		addr = c.destination
	} else {
		addr = c.destination.UDPAddr()
	}
	return
}

func (c *serverPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = binary.Write(c.ExtendedConn, binary.BigEndian, uint16(len(p)))
	if err != nil {
		return
	}
	return c.ExtendedConn.Write(p)
}

func (c *serverPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	var packetLen uint16
	err = binary.Read(c.ExtendedConn, binary.BigEndian, &packetLen)
	if err != nil {
		return
	}

	_, err = buffer.ReadFullFrom(c.ExtendedConn, int(packetLen))
	if err != nil {
		return
	}

	destination = c.destination
	return
}

func (c *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	packetLen := buffer.Len()
	binary.BigEndian.PutUint16(buffer.ExtendHeader(2), uint16(packetLen))
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *serverPacketConn) FrontHeadroom() int {
	return 2
}

func (c *serverPacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *serverPacketConn) Upstream() any {
	return c.ExtendedConn
}
