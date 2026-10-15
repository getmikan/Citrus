package dns

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockingService holds every query until release is closed, or until the
// query's context ends.
type blockingService struct {
	started chan struct{}
	release chan struct{}
}

func (b *blockingService) ServeMsg(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	b.started <- struct{}{}
	select {
	case <-b.release:
		m := new(D.Msg)
		m.SetReply(msg)
		return m, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// deadlineService reports the deadline of the query's context.
type deadlineService struct {
	deadline time.Time
	ok       bool
}

func (d *deadlineService) ServeMsg(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	d.deadline, d.ok = ctx.Deadline()
	<-ctx.Done()
	return nil, ctx.Err()
}

type recordWriter struct {
	mu   sync.Mutex
	msgs []*D.Msg
}

func (w *recordWriter) WriteMsg(m *D.Msg) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.msgs = append(w.msgs, m)
	return nil
}

func (w *recordWriter) written() []*D.Msg {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]*D.Msg(nil), w.msgs...)
}

func (w *recordWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (w *recordWriter) RemoteAddr() net.Addr        { return &net.UDPAddr{} }
func (w *recordWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *recordWriter) Close() error                { return nil }
func (w *recordWriter) TsigStatus() error           { return nil }
func (w *recordWriter) TsigTimersOnly(bool)         {}
func (w *recordWriter) Hijack()                     {}

func query(name string) *D.Msg {
	m := new(D.Msg)
	m.SetQuestion(D.Fqdn(name), D.TypeA)
	return m
}

func TestServerInflightCap(t *testing.T) {
	const limit = 4
	svc := &blockingService{started: make(chan struct{}, limit), release: make(chan struct{})}
	s := newServer(svc)
	s.inflight = make(chan struct{}, limit)

	// fill every slot with queries that block in the service
	var wg sync.WaitGroup
	held := &recordWriter{}
	for i := 0; i < limit; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.TCPHandler().ServeDNS(held, query("held.example"))
		}()
	}
	for i := 0; i < limit; i++ {
		select {
		case <-svc.started:
		case <-time.After(5 * time.Second):
			t.Fatal("queries did not reach the service")
		}
	}

	// over the cap TCP answers SERVFAIL at once, without reaching the service
	tcpOver := &recordWriter{}
	done := make(chan struct{})
	go func() {
		s.TCPHandler().ServeDNS(tcpOver, query("over.example"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TCP query over the cap blocked")
	}
	if got := tcpOver.written(); assert.Len(t, got, 1) {
		assert.Equal(t, D.RcodeServerFailure, got[0].Rcode)
	}

	// over the cap UDP drops the query without a reply
	udpOver := &recordWriter{}
	done = make(chan struct{})
	go func() {
		s.UDPHandler().ServeDNS(udpOver, query("over.example"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UDP query over the cap blocked")
	}
	assert.Empty(t, udpOver.written())
	assert.Empty(t, svc.started, "a query over the cap reached the service")

	// released slots serve new queries again
	close(svc.release)
	wg.Wait()
	assert.Len(t, held.written(), limit)
	for _, m := range held.written() {
		assert.Equal(t, D.RcodeSuccess, m.Rcode)
	}

	after := &recordWriter{}
	go func() { <-svc.started }()
	s.UDPHandler().ServeDNS(after, query("after.example"))
	if got := after.written(); assert.Len(t, got, 1) {
		assert.Equal(t, D.RcodeSuccess, got[0].Rcode)
	}
	assert.Empty(t, s.inflight, "slots leaked")
}

func TestServerQueryTimeout(t *testing.T) {
	assert.Equal(t, queryTimeout, newServer(nil).queryTimeout)
	assert.Greater(t, queryTimeout, time.Duration(0))

	svc := &deadlineService{}
	s := newServer(svc)
	s.queryTimeout = 50 * time.Millisecond

	w := &recordWriter{}
	start := time.Now()
	done := make(chan struct{})
	go func() {
		s.TCPHandler().ServeDNS(w, query("slow.example"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("query outlived its timeout")
	}

	require.True(t, svc.ok, "query context has no deadline")
	assert.WithinDuration(t, start.Add(s.queryTimeout), svc.deadline, time.Second)
	if got := w.written(); assert.Len(t, got, 1) {
		assert.Equal(t, D.RcodeServerFailure, got[0].Rcode)
	}
	assert.Empty(t, s.inflight, "slot leaked after timeout")
}
