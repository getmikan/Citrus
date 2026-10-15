package shadowquic

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/stretchr/testify/require"
)

// newTestConnState builds a connState without a QUIC connection: the receive
// bookkeeping does not touch it.
func newTestConnState(t *testing.T) *connState {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &connState{
		ctx:        ctx,
		cancel:     cancel,
		activeSend: make(map[uint16]struct{}),
		recv:       make(map[uint16]*recvSlot),
	}
}

func newTestAssociation() *association {
	return &association{
		input:  make(chan receivedPacket, packetInputQueue),
		closed: make(chan struct{}),
	}
}

func testSocksAddr() socks5.Addr {
	return socks5.ParseAddr("127.0.0.1:53")
}

func (s *connState) pendingStats() (ids, bytes, slots int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, slot := range s.recv {
		if slot.target == nil {
			slots++
		}
	}
	return s.pendingIDs, s.pendingBytes, slots
}

// Datagrams for IDs that no control message bound are kept within a
// connection-wide budget, not 32 copies for every one of the 65536 IDs.
func TestPendingRecvBudget(t *testing.T) {
	s := newTestConnState(t)
	payload := bytes.Repeat([]byte{1}, 1200)
	for id := 0; id < 1<<16; id++ {
		for i := 0; i < 4; i++ {
			s.feedDatagram(uint16(id), payload)
		}
	}
	ids, pendingBytes, slots := s.pendingStats()
	require.LessOrEqual(t, slots, maxPendingRecvIDs)
	require.Equal(t, slots, ids)
	require.LessOrEqual(t, pendingBytes, maxPendingRecvBytes)

	// a waiter for yet another ID is turned away instead of parking
	_, err := s.waitRecvTarget(60000)
	require.ErrorIs(t, err, errPendingRecvRejected)
}

// Packets that arrive before their association is bound are delivered once
// it is, and the budget is given back.
func TestPendingRecvDeliveredOnBind(t *testing.T) {
	s := newTestConnState(t)
	for i := 0; i < 3; i++ {
		s.feedDatagram(7, []byte{byte(i)})
	}
	ids, pendingBytes, _ := s.pendingStats()
	require.Equal(t, 1, ids)
	require.Equal(t, 3, pendingBytes)

	type waitResult struct {
		target *recvTarget
		err    error
	}
	waited := make(chan waitResult, 1)
	go func() {
		target, err := s.waitRecvTarget(8)
		waited <- waitResult{target, err}
	}()

	assoc := newTestAssociation()
	s.storeRecv(7, assoc, testSocksAddr())
	for i := 0; i < 3; i++ {
		select {
		case packet := <-assoc.input:
			require.Equal(t, []byte{byte(i)}, packet.data)
		case <-time.After(time.Second):
			t.Fatal("pending packet not delivered")
		}
	}
	require.Eventually(t, func() bool { ids, _, _ := s.pendingStats(); return ids == 1 }, time.Second, time.Millisecond)
	s.storeRecv(8, assoc, testSocksAddr())
	select {
	case res := <-waited:
		require.NoError(t, res.err)
		require.Same(t, assoc, res.target.assoc)
	case <-time.After(time.Second):
		t.Fatal("stream waiter not woken by the binding")
	}
	ids, pendingBytes, _ = s.pendingStats()
	require.Zero(t, ids)
	require.Zero(t, pendingBytes)

	// bound IDs keep working past the budget
	s.feedDatagram(7, []byte("late"))
	select {
	case packet := <-assoc.input:
		require.Equal(t, []byte("late"), packet.data)
	case <-time.After(time.Second):
		t.Fatal("packet for a bound id not delivered")
	}
}

// A stream waiting for a binding that never comes gives up after the TTL.
func TestPendingRecvWaiterTimesOut(t *testing.T) {
	s := newTestConnState(t)
	s.feedDatagram(9, []byte("x"))
	s.mu.Lock()
	s.recv[9].expires = time.Now().Add(50 * time.Millisecond)
	s.mu.Unlock()

	start := time.Now()
	_, err := s.waitRecvTarget(9)
	require.ErrorIs(t, err, errPendingRecvRejected)
	require.Less(t, time.Since(start), 5*time.Second)
	ids, pendingBytes, slots := s.pendingStats()
	require.Zero(t, ids)
	require.Zero(t, pendingBytes)
	require.Zero(t, slots)
}

// Expired pending IDs make room for new ones once the budget is full.
func TestPendingRecvExpiry(t *testing.T) {
	s := newTestConnState(t)
	for id := 0; id < maxPendingRecvIDs; id++ {
		s.feedDatagram(uint16(id), []byte("x"))
	}
	s.feedDatagram(maxPendingRecvIDs, []byte("x"))
	_, _, slots := s.pendingStats()
	require.Equal(t, maxPendingRecvIDs, slots)

	s.mu.Lock()
	for _, slot := range s.recv {
		slot.expires = time.Now().Add(-time.Second)
	}
	s.mu.Unlock()
	s.feedDatagram(maxPendingRecvIDs, []byte("x"))
	ids, pendingBytes, slots := s.pendingStats()
	require.Equal(t, 1, ids)
	require.Equal(t, 1, slots)
	require.Equal(t, 1, pendingBytes)
}
