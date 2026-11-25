package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/inbounduser"
	"github.com/metacubex/mihomo/log"

	amneziav3 "github.com/metacubex/amneziawg-go/device"
	amnezia "github.com/metacubex/amneziawg-go/device_v1"
	"github.com/metacubex/mipstack"
	"github.com/metacubex/wireguard-go/device"
	"github.com/metacubex/wireguard-go/tun"
)

const (
	defaultMTU    = 1408
	defaultIPv4   = "10.66.66.0/24"
	udpIdleWindow = 60 * time.Second
)

// wgDevice is the part of the two AmneziaWG implementations and of
// wireguard-go's device the listener uses.
type wgDevice interface {
	IpcSet(string) error
	Up() error
	Close()
}

// Listener is a WireGuard / AmneziaWG inbound.
//
// It runs entirely in userspace: the device encrypts and decrypts, a userspace
// IP stack turns the decrypted packets into connections, and those go into the
// tunnel like the connections of any other inbound. No TUN device, no
// NET_ADMIN and no wg-quick are involved, so the node keeps its
// cap_drop: ALL + NET_BIND_SERVICE.
type Listener struct {
	closed    atomic.Bool
	config    LC.WireGuardServer
	tunnel    C.Tunnel
	dev       wgDevice
	stack     *mipstack.Stack
	udp       net.PacketConn
	bind      *Bind
	users     *inbounduser.Set[[32]byte]
	inName    string
	additions []inbound.Addition

	private  [32]byte
	pool4    netip.Prefix
	pool6    netip.Prefix
	poolAddr []netip.Addr

	// peers and byAddress are replaced as a whole under mu: a forwarder callback
	// reads them without a lock when it names the user of a connection.
	mu        sync.RWMutex
	peers     []peer
	byAddress map[netip.Addr]string
}

// New starts the listener: the UDP socket, the userspace stack and the device.
func New(config LC.WireGuardServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-WIREGUARD"),
			inbound.WithSpecialRules(""),
		}
	}
	inName := "DEFAULT-WIREGUARD"
	for _, addition := range additions {
		if name := additionName(addition); name != "" {
			inName = name
			break
		}
	}

	private, err := decodeKey(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("wireguard: private-key: %w", err)
	}
	if err := ValidateAmneziaWG(config.AmneziaWG); err != nil {
		return nil, err
	}

	mtu := config.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	if mtu < 1280 || mtu > 1500 {
		return nil, fmt.Errorf("wireguard: mtu %d is outside 1280..1500", mtu)
	}

	ipv4 := config.IPv4CIDR
	if ipv4 == "" && config.IPv6CIDR == "" {
		ipv4 = defaultIPv4
	}

	sl := &Listener{
		config:    config,
		tunnel:    tunnel,
		inName:    inName,
		additions: additions,
		private:   private,
	}

	if ipv4 != "" {
		prefix, _, err := parsePool(ipv4)
		if err != nil {
			return nil, fmt.Errorf("wireguard: ipv4-cidr: %w", err)
		}
		sl.pool4 = prefix
		sl.poolAddr = append(sl.poolAddr, poolAddresses(prefix)...)
	}
	if config.IPv6CIDR != "" {
		prefix, _, err := parsePool(config.IPv6CIDR)
		if err != nil {
			return nil, fmt.Errorf("wireguard: ipv6-cidr: %w", err)
		}
		sl.pool6 = prefix
		sl.poolAddr = append(sl.poolAddr, poolAddresses(prefix)...)
	}

	sl.users, _ = inbounduser.New(userKey, inbounduser.FromMap(config.Users))

	bind, err := NewBind(lc, config.Listen)
	if err != nil {
		return nil, err
	}
	sl.bind = bind

	local := make([]netip.Prefix, 0, 2)
	if sl.pool4.IsValid() {
		local = append(local, sl.pool4)
	}
	if sl.pool6.IsValid() {
		local = append(local, sl.pool6)
	}

	stack, err := mipstack.New(mipstack.Config{
		LocalAddresses: local,
		// The tunnel's destinations are the whole internet, so the stack admits
		// packets whose destination it does not own and hands them to the
		// forwarders below.
		Promiscuous: true,
		MTU:         uint32(mtu),
	})
	if err != nil {
		_ = bind.Shutdown()
		return nil, fmt.Errorf("wireguard: create stack: %w", err)
	}
	sl.stack = stack

	if _, err := mipstack.NewTCPForwarder(stack, mipstack.TCPForwarderOptions{}, sl.forwardTCP); err != nil {
		_ = stack.Close()
		_ = bind.Shutdown()
		return nil, fmt.Errorf("wireguard: tcp forwarder: %w", err)
	}
	if _, err := mipstack.NewUDPForwarder(stack, mipstack.UDPForwarderOptions{}, sl.forwardUDP); err != nil {
		_ = stack.Close()
		_ = bind.Shutdown()
		return nil, fmt.Errorf("wireguard: udp forwarder: %w", err)
	}

	// The stack has to be running before the device reads from it: its Read
	// reports "not started" otherwise, and the device closes itself on a read
	// error.
	if err := stack.Start(); err != nil {
		_ = stack.Close()
		_ = bind.Shutdown()
		return nil, fmt.Errorf("wireguard: start stack: %w", err)
	}

	dev := &stackDevice{stack: stack, events: make(chan tun.Event, 1), mtu: mtu}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			log.SingLogger.Debug(fmt.Sprintf("[WG](%s) %s", inName, fmt.Sprintf(format, args...)))
		},
		Errorf: func(format string, args ...any) {
			log.SingLogger.Error(fmt.Sprintf("[WG](%s) %s", inName, fmt.Sprintf(format, args...)))
		},
	}
	var wgDev wgDevice
	if config.AmneziaWG != nil {
		if config.AmneziaWG.Version == 3 {
			wgDev = amneziav3.NewDevice(dev, sl.bind, logger, config.Workers)
		} else {
			wgDev = amnezia.NewDevice(dev, sl.bind, logger, config.Workers)
		}
	} else {
		wgDev = device.NewDevice(dev, sl.bind, logger, config.Workers)
	}
	sl.dev = wgDev

	if err := sl.applyUsers(); err != nil {
		wgDev.Close()
		_ = bind.Shutdown()
		return nil, err
	}
	// The tun event reader brings the device up: the adapter publishes EventUp
	// as soon as the device starts listening for it.
	if err := wgDev.Up(); err != nil {
		wgDev.Close()
		_ = bind.Shutdown()
		return nil, fmt.Errorf("wireguard: up: %w", err)
	}

	return sl, nil
}

func additionName(a inbound.Addition) string {
	m := &C.Metadata{}
	a(m)
	return m.InName
}

// Close stops the device and the socket. Closing the device first stops the
// packet loops, so the stack and the socket go after it.
func (l *Listener) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	// The device closes the bind, the stack and the tun side itself; the socket
	// is only closed here for the case the device never got to it.
	l.dev.Close()
	return l.stack.Close()
}

func (l *Listener) Config() string { return l.config.String() }

func (l *Listener) AddrList() []net.Addr {
	pc := l.bind.packetConn()
	if pc == nil {
		return nil
	}
	return []net.Addr{pc.LocalAddr()}
}

// Users returns the current users (Name = user, Secret = slot secret).
func (l *Listener) Users() []C.InboundUser { return l.users.Users() }

// ReplaceUsers swaps the users and rewrites the peers of the device in place:
// a removed or re-keyed user loses its peer, which is what closes its tunnel.
func (l *Listener) ReplaceUsers(users []C.InboundUser) (inbounduser.Change, error) {
	if err := inbounduser.NoFlow("wireguard", users); err != nil {
		return inbounduser.Change{}, err
	}
	change, err := l.users.Replace(users)
	if err != nil {
		return inbounduser.Change{}, err
	}
	if err := l.applyUsers(); err != nil {
		return change, err
	}
	return change, nil
}

// userKey maps an inbound user to the public key of its peer.
func userKey(user C.InboundUser) ([32]byte, error) {
	return UserKey(user.Secret)
}

// applyUsers renders the peers of the current user set and pushes them to the
// device in one set operation.
func (l *Listener) applyUsers() error {
	users := l.users.Users()
	keys := make([][32]byte, 0, len(users))
	names := make(map[[32]byte]string, len(users))
	for _, user := range users {
		key, err := UserKey(user.Secret)
		if err != nil {
			return err
		}
		keys = append(keys, key)
		names[key] = user.Name
	}

	addresses := assignAddresses(keys, l.poolAddr)
	peers := make([]peer, 0, len(keys))
	byAddress := make(map[netip.Addr]string, len(keys))
	for _, key := range keys {
		addr, ok := addresses[key]
		if !ok {
			return fmt.Errorf("wireguard: no free tunnel address for %q", names[key])
		}
		peers = append(peers, peer{user: names[key], publicKey: key, address: addr})
		byAddress[addr] = names[key]
	}

	conf, err := ipcConfig(l.private, l.config.AmneziaWG, sortedPeers(peers))
	if err != nil {
		return err
	}
	if err := l.dev.IpcSet(conf); err != nil {
		return fmt.Errorf("wireguard: apply peers: %w", err)
	}

	l.mu.Lock()
	l.peers = peers
	l.byAddress = byAddress
	l.mu.Unlock()
	return nil
}

// userOf names the user that owns an inner address.
func (l *Listener) userOf(addr netip.Addr) string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.byAddress[addr.Unmap()]
}

// baseMetadata is the metadata common to every connection of a peer: the
// inbound name and user, and the peer's inner address as the source.
func (l *Listener) baseMetadata(src netip.AddrPort, user string) *C.Metadata {
	md := &C.Metadata{
		Type:    C.WIREGUARD,
		InName:  l.inName,
		SrcIP:   src.Addr().Unmap(),
		SrcPort: src.Port(),
	}
	inbound.ApplyAdditions(md, l.additions...)
	md.InUser = user
	if raw := net.TCPAddrFromAddrPort(src); raw != nil {
		md.RawSrcAddr = raw
	}
	return md
}

// forwardTCP bridges one TCP connection of the stack into the tunnel.
func (l *Listener) forwardTCP(req *mipstack.TCPForwarderRequest) {
	flow := req.Flow()
	user := l.userOf(flow.Source.Addr())
	if user == "" {
		// Every peer has an inner address; a packet from anywhere else means the
		// device let through what the listener does not know.
		_ = req.Drop()
		return
	}
	conn, err := req.Accept(context.Background())
	if err != nil {
		return
	}
	go l.serveTCP(conn, flow, user)
}

func (l *Listener) serveTCP(conn net.Conn, flow mipstack.ForwarderFlow, user string) {
	defer conn.Close()

	md := l.baseMetadata(flow.Source, user)
	md.NetWork = C.TCP
	md.DstIP = flow.Destination.Addr().Unmap()
	md.DstPort = flow.Destination.Port()
	if raw := net.TCPAddrFromAddrPort(flow.Destination); raw != nil {
		md.RawDstAddr = raw
	}
	l.tunnel.HandleTCPConn(conn, md)
}

// forwardUDP bridges one UDP flow of the stack into the tunnel.
func (l *Listener) forwardUDP(req *mipstack.UDPForwarderRequest) {
	flow := req.Flow()
	user := l.userOf(flow.Source.Addr())
	if user == "" {
		_ = req.Drop()
		return
	}
	payload := append([]byte(nil), req.Payload()...)
	conn, err := req.Accept()
	if err != nil {
		return
	}
	session := &udpSession{
		conn:     conn,
		listener: l,
		flow:     flow,
		user:     user,
	}
	session.deliver(payload)
	go session.run()
}

// udpSession is one UDP flow of one peer. WireGuard has no sessions, so the
// flow is the four-tuple the stack gives the forwarder; the nat key of the
// tunnel stays the same for every datagram of the peer and destination.
type udpSession struct {
	conn     *mipstack.UDPConn
	listener *Listener
	flow     mipstack.ForwarderFlow
	user     string
	closed   atomic.Bool
}

func (s *udpSession) run() {
	defer s.conn.Close()
	buf := make([]byte, 65535)
	for {
		if s.closed.Load() {
			return
		}
		_ = s.conn.SetReadDeadline(time.Now().Add(udpIdleWindow))
		n, err := s.conn.Read(buf)
		if err != nil {
			return
		}
		s.deliver(append([]byte(nil), buf[:n]...))
	}
}

// deliver hands one datagram to the tunnel. The packet's WriteBack is the
// connected socket, so a reply leaves the stack with the original destination
// as its source address.
func (s *udpSession) deliver(payload []byte) {
	if s.closed.Load() {
		return
	}
	md := s.listener.baseMetadata(s.flow.Source, s.user)
	md.NetWork = C.UDP
	md.DstIP = s.flow.Destination.Addr().Unmap()
	md.DstPort = s.flow.Destination.Port()
	if raw := net.UDPAddrFromAddrPort(s.flow.Destination); raw != nil {
		md.RawDstAddr = raw
	}
	packet := &udpPacket{session: s, payload: payload}
	s.listener.tunnel.HandleUDPPacket(C.NewPacketAdapter(packet, md), md)
}

type udpPacket struct {
	session *udpSession
	payload []byte
}

func (p *udpPacket) Data() []byte { return p.payload }

// WriteBack writes a reply to the peer. The socket is connected to the peer
// and bound to the destination, so the address the tunnel passes is only a
// hint: the wire source is always the original destination.
func (p *udpPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	if p.session.closed.Load() {
		return 0, net.ErrClosed
	}
	return p.session.conn.Write(b)
}

func (p *udpPacket) Drop() { p.payload = nil }

// LocalAddr is the peer's inner address: the nat key of the tunnel is built
// from it, so every datagram of a flow lands in the same session.
func (p *udpPacket) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(p.session.flow.Source) }

func (p *udpPacket) InAddr() net.Addr { return nil }

// stackDevice adapts the mipstack stack to tun.Device, which is what the
// WireGuard device expects: packets the stack produces are read from the
// device's tun side, packets from peers are written into it.
type stackDevice struct {
	stack     *mipstack.Stack
	events    chan tun.Event
	mtu       int
	closeOnce sync.Once
}

var _ tun.Device = (*stackDevice)(nil)

func (d *stackDevice) File() *os.File { return nil }

func (d *stackDevice) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	return d.stack.Read(buffers, sizes, offset)
}

func (d *stackDevice) Write(buffers [][]byte, offset int) (int, error) {
	return d.stack.Write(buffers, offset)
}

func (d *stackDevice) MTU() (int, error) { return d.mtu, nil }

func (d *stackDevice) Name() (string, error) { return "wireguard inbound stack", nil }

func (d *stackDevice) Events() <-chan tun.Event { return d.events }

func (d *stackDevice) BatchSize() int { return d.stack.BatchSize() }

// Close stops the device's view of the tun side. The stack must go too: the
// device's read loop is blocked in Stack.Read, and Close waits for it, so
// closing only the event channel would hang the shutdown.
func (d *stackDevice) Close() error {
	var err error
	d.closeOnce.Do(func() {
		close(d.events)
		err = d.stack.Close()
	})
	return err
}
