package sing_tun

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
	D "github.com/miekg/dns"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testDnsAddr = netip.MustParseAddrPort("198.18.0.2:53")

func dnsQueryBuffer(t *testing.T) *buf.Buffer {
	t.Helper()
	msg := new(D.Msg)
	msg.SetQuestion("example.com.", D.TypeA)
	packed, err := msg.Pack()
	require.NoError(t, err)
	buffer := buf.NewSize(4096)
	_, _ = buffer.Write(packed)
	return buffer
}

type recordWriter struct {
	mu      sync.Mutex
	packets int
	written chan struct{}
}

func newRecordWriter() *recordWriter {
	return &recordWriter{written: make(chan struct{}, 64)}
}

func (w *recordWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	w.mu.Lock()
	w.packets++
	w.mu.Unlock()
	w.written <- struct{}{}
	return nil
}

func (w *recordWriter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.packets
}

// fillDnsRelaySlots takes every relay slot, as a flood of slow queries would.
func fillDnsRelaySlots(t *testing.T) {
	t.Helper()
	for i := 0; i < maxDnsRelayInFlight; i++ {
		require.True(t, acquireDnsRelaySlot())
	}
	t.Cleanup(func() {
		for len(dnsRelaySlots) > 0 {
			releaseDnsRelaySlot()
		}
	})
}

func waitDnsRelaySlotsFree(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool { return len(dnsRelaySlots) == 0 }, 5*time.Second, 10*time.Millisecond)
}

func TestDnsHijackPacketRelayed(t *testing.T) {
	h := &ListenerHandler{DnsAddrPorts: []netip.AddrPort{testDnsAddr}}
	w := newRecordWriter()
	metadata := M.Metadata{Source: M.ParseSocksaddr("198.18.0.1:40000"), Destination: M.SocksaddrFromNetIP(testDnsAddr)}
	h.NewPacket(context.Background(), metadata.Source.AddrPort(), dnsQueryBuffer(t), metadata, func(network.PacketConn) network.PacketWriter { return w })
	select {
	case <-w.written:
	case <-time.After(5 * time.Second):
		t.Fatal("hijacked query was not answered")
	}
	waitDnsRelaySlotsFree(t)
}

func TestDnsHijackPacketDroppedWhenSaturated(t *testing.T) {
	fillDnsRelaySlots(t)
	h := &ListenerHandler{DnsAddrPorts: []netip.AddrPort{testDnsAddr}}
	initCalled := false
	metadata := M.Metadata{Source: M.ParseSocksaddr("198.18.0.1:40000"), Destination: M.SocksaddrFromNetIP(testDnsAddr)}
	h.NewPacket(context.Background(), metadata.Source.AddrPort(), dnsQueryBuffer(t), metadata, func(network.PacketConn) network.PacketWriter {
		initCalled = true
		return newRecordWriter()
	})
	assert.False(t, initCalled, "a query over the in-flight limit must be dropped")
	assert.Equal(t, maxDnsRelayInFlight, len(dnsRelaySlots))
}

// queuePacketConn hands out queued queries, then reports closed.
type queuePacketConn struct {
	*recordWriter
	queue []*buf.Buffer
}

func (c *queuePacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if len(c.queue) == 0 {
		return M.Socksaddr{}, net.ErrClosed
	}
	next := c.queue[0]
	c.queue = c.queue[1:]
	_, _ = buffer.Write(next.Bytes())
	next.Release()
	return M.SocksaddrFromNetIP(testDnsAddr), nil
}

func (c *queuePacketConn) Close() error                     { return nil }
func (c *queuePacketConn) LocalAddr() net.Addr              { return M.SocksaddrFromNetIP(testDnsAddr).UDPAddr() }
func (c *queuePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *queuePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *queuePacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestDnsHijackPacketConnectionLimit(t *testing.T) {
	h := &ListenerHandler{DnsAddrPorts: []netip.AddrPort{testDnsAddr}}
	metadata := M.Metadata{Source: M.ParseSocksaddr("198.18.0.1:40000"), Destination: M.SocksaddrFromNetIP(testDnsAddr)}

	t.Run("saturated", func(t *testing.T) {
		fillDnsRelaySlots(t)
		conn := &queuePacketConn{recordWriter: newRecordWriter(), queue: []*buf.Buffer{dnsQueryBuffer(t), dnsQueryBuffer(t)}}
		require.NoError(t, h.NewPacketConnection(context.Background(), conn, metadata))
		assert.Zero(t, conn.count())
		assert.Equal(t, maxDnsRelayInFlight, len(dnsRelaySlots))
	})

	t.Run("free", func(t *testing.T) {
		conn := &queuePacketConn{recordWriter: newRecordWriter(), queue: []*buf.Buffer{dnsQueryBuffer(t)}}
		// NewPacketConnection stops writing once it returns, so keep the conn
		// open until the answer is out by blocking the final read.
		done := make(chan error, 1)
		go func() { done <- h.NewPacketConnection(context.Background(), &blockingTail{conn}, metadata) }()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("hijacked query was not answered")
		}
		assert.Equal(t, 1, conn.count())
		waitDnsRelaySlotsFree(t)
	})
}

// blockingTail delays the closing read until one answer has been written.
type blockingTail struct {
	*queuePacketConn
}

func (c *blockingTail) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if len(c.queue) == 0 {
		<-c.written
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
	return c.queuePacketConn.ReadPacket(buffer)
}
