package shadowquic

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/jls-quic-go"
)

// Packets (datagrams) and UDP streams may reach the peer before the control
// message that binds their ID to an association. Such IDs are kept as
// pending, within a connection-wide budget:
//
//   - maxPendingPacketsPerID packets are kept per pending ID;
//   - at most maxPendingRecvIDs IDs are pending at once, and they hold at
//     most maxPendingRecvBytes of copied packets together; past either limit
//     packets for further unknown IDs are dropped (UDP may be lost) and
//     streams for them are closed;
//   - a pending ID that has not been bound within pendingRecvTTL is dropped,
//     and a stream waiting for its binding gives up.
//
// A legitimate peer sends the control message right before the data, so an
// ID stays pending for about one RTT and only a few are pending at once.
const (
	maxPendingPacketsPerID = 32
	maxPendingRecvIDs      = 256
	maxPendingRecvBytes    = 1 << 20
	pendingRecvTTL         = 10 * time.Second
)

var errPendingRecvRejected = errors.New("shadowquic: association id not bound")

type udpMode uint8

const (
	udpModeDatagram udpMode = iota
	udpModeStream
)

type receivedPacket struct {
	data      []byte
	addr      net.Addr
	socksAddr socks5.Addr
}

type connState struct {
	quicConn *quic.Conn
	ctx      context.Context
	cancel   context.CancelFunc

	mu         sync.Mutex
	nextID     uint16
	activeSend map[uint16]struct{}
	recv       map[uint16]*recvSlot

	// pending (not yet bound) receive IDs, see maxPendingRecvIDs
	pendingIDs   int
	pendingBytes int
}

type recvSlot struct {
	ready   chan struct{} // closed once bound, or once dropped while pending
	target  *recvTarget
	pending [][]byte
	expires time.Time // for a pending slot
	dropped bool      // a pending slot that was dropped from recv
}

type recvTarget struct {
	assoc *association
	addr  socks5.Addr
	net   net.Addr
}

func newConnState(quicConn *quic.Conn) *connState {
	ctx, cancel := context.WithCancel(quicConn.Context())
	state := &connState{
		quicConn:   quicConn,
		ctx:        ctx,
		cancel:     cancel,
		activeSend: make(map[uint16]struct{}),
		recv:       make(map[uint16]*recvSlot),
	}
	go state.handleDatagrams()
	go state.handleUniStreams()
	go func() {
		<-quicConn.Context().Done()
		cancel()
	}()
	return state
}

func (s *connState) closed() bool {
	select {
	case <-s.ctx.Done():
		return true
	default:
		return false
	}
}

func (s *connState) closeWithError(code quic.ApplicationErrorCode, message string) error {
	s.cancel()
	return s.quicConn.CloseWithError(code, message)
}

// pendingSlotLocked returns the slot of id, adding a pending one if there is
// none and the budget allows. It returns nil when the budget is exhausted.
func (s *connState) pendingSlotLocked(id uint16) *recvSlot {
	if slot := s.recv[id]; slot != nil {
		return slot
	}
	now := time.Now()
	if s.pendingIDs >= maxPendingRecvIDs || s.pendingBytes >= maxPendingRecvBytes {
		s.expirePendingLocked(now)
		if s.pendingIDs >= maxPendingRecvIDs || s.pendingBytes >= maxPendingRecvBytes {
			return nil
		}
	}
	slot := &recvSlot{ready: make(chan struct{}), expires: now.Add(pendingRecvTTL)}
	s.recv[id] = slot
	s.pendingIDs++
	return slot
}

// expirePendingLocked drops the pending slots past their TTL.
func (s *connState) expirePendingLocked(now time.Time) {
	for id, slot := range s.recv {
		if slot.target == nil && !now.Before(slot.expires) {
			s.dropPendingLocked(id, slot)
		}
	}
}

// dropPendingLocked removes a pending slot and wakes its waiters.
func (s *connState) dropPendingLocked(id uint16, slot *recvSlot) {
	if slot.target != nil || slot.dropped {
		return
	}
	if s.recv[id] == slot {
		delete(s.recv, id)
	}
	slot.dropped = true
	s.pendingIDs--
	for _, packet := range slot.pending {
		s.pendingBytes -= len(packet)
	}
	slot.pending = nil
	close(slot.ready)
}

func (s *connState) handleDatagrams() {
	for {
		message, err := s.quicConn.ReceiveDatagram(s.ctx)
		if err != nil {
			s.cancel()
			return
		}
		id, payload, err := DecodeDatagram(message)
		if err != nil {
			continue
		}
		s.feedDatagram(id, payload)
	}
}

func (s *connState) handleUniStreams() {
	for {
		stream, err := s.quicConn.AcceptUniStream(s.ctx)
		if err != nil {
			s.cancel()
			return
		}
		go s.handleUniStream(stream)
	}
}

func (s *connState) handleUniStream(stream *quic.ReceiveStream) {
	defer stream.CancelRead(0)

	id, err := ReadUint16(stream)
	if err != nil {
		return
	}
	target, err := s.waitRecvTarget(id)
	if err != nil {
		return
	}

	for {
		length, err := ReadUint16(stream)
		if err != nil {
			return
		}
		payload := make([]byte, int(length))
		if _, err = io.ReadFull(stream, payload); err != nil {
			return
		}
		target.assoc.deliver(receivedPacket{
			data:      payload,
			addr:      target.net,
			socksAddr: target.addr,
		})
	}
}

func (s *connState) feedDatagram(id uint16, payload []byte) {
	s.mu.Lock()
	slot := s.recv[id]
	if slot != nil && slot.target != nil {
		target := slot.target
		s.mu.Unlock()
		target.assoc.deliver(receivedPacket{
			data:      payload,
			addr:      target.net,
			socksAddr: target.addr,
		})
		return
	}
	if slot == nil {
		slot = s.pendingSlotLocked(id)
		if slot == nil {
			s.mu.Unlock()
			return
		}
	}
	if len(slot.pending) < maxPendingPacketsPerID && s.pendingBytes+len(payload) <= maxPendingRecvBytes {
		packet := make([]byte, len(payload))
		copy(packet, payload)
		slot.pending = append(slot.pending, packet)
		s.pendingBytes += len(packet)
	}
	s.mu.Unlock()
}

func (s *connState) waitRecvTarget(id uint16) (*recvTarget, error) {
	s.mu.Lock()
	slot := s.pendingSlotLocked(id)
	if slot == nil {
		s.mu.Unlock()
		return nil, errPendingRecvRejected
	}
	if slot.target != nil {
		target := slot.target
		s.mu.Unlock()
		return target, nil
	}
	ready := slot.ready
	wait := time.Until(slot.expires)
	s.mu.Unlock()

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ready:
	case <-timer.C:
	case <-s.ctx.Done():
		return nil, net.ErrClosed
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if slot.target != nil {
		return slot.target, nil
	}
	s.dropPendingLocked(id, slot)
	return nil, errPendingRecvRejected
}

func (s *connState) storeRecv(id uint16, assoc *association, addr socks5.Addr) {
	netAddr := AddrToNetAddr(addr)

	s.mu.Lock()
	slot := s.recv[id]
	if slot == nil {
		// bound IDs are not part of the pending budget
		slot = &recvSlot{ready: make(chan struct{})}
		close(slot.ready)
		s.recv[id] = slot
	} else if slot.target == nil {
		s.pendingIDs--
		for _, packet := range slot.pending {
			s.pendingBytes -= len(packet)
		}
		close(slot.ready)
	}
	slot.target = &recvTarget{assoc: assoc, addr: addr, net: netAddr}
	pending := slot.pending
	slot.pending = nil
	s.mu.Unlock()

	for _, packet := range pending {
		assoc.deliver(receivedPacket{
			data:      packet,
			addr:      netAddr,
			socksAddr: addr,
		})
	}
}

func (s *connState) removeRecvIDs(assoc *association, ids map[uint16]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id := range ids {
		slot := s.recv[id]
		if slot != nil && slot.target != nil && slot.target.assoc == assoc {
			delete(s.recv, id)
		}
	}
}

func (s *connState) allocSendID() (uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	start := s.nextID
	for {
		id := s.nextID
		s.nextID++
		if _, exists := s.activeSend[id]; !exists {
			s.activeSend[id] = struct{}{}
			return id, nil
		}
		if s.nextID == start {
			return 0, errorsTooManyUDPContexts{}
		}
	}
}

func (s *connState) releaseSendIDs(ids map[uint16]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id := range ids {
		delete(s.activeSend, id)
	}
}

type errorsTooManyUDPContexts struct{}

func (errorsTooManyUDPContexts) Error() string {
	return "shadowquic: too many udp contexts"
}
