package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testIPs(n int) []netip.Addr {
	ips := make([]netip.Addr, n)
	for i := range ips {
		ips[i] = netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
	}
	return ips
}

type closeTrackingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func newTrackingConn() *closeTrackingConn {
	a, b := net.Pipe()
	_ = b.Close()
	return &closeTrackingConn{Conn: a}
}

func TestBoundedParallelDialCapsFanOut(t *testing.T) {
	var inFlight, maxInFlight, total atomic.Int32
	dial := func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
		total.Add(1)
		n := inFlight.Add(1)
		for {
			m := maxInFlight.Load()
			if n <= m || maxInFlight.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		inFlight.Add(-1)
		return nil, errors.New("refused")
	}

	conn, err := boundedParallelDial(context.Background(), testIPs(200), dial)
	if conn != nil || err == nil {
		t.Fatalf("expected failure, got conn=%v err=%v", conn, err)
	}
	if got := maxInFlight.Load(); got > parallelDialMaxInFlight {
		t.Fatalf("max in-flight %d > %d", got, parallelDialMaxInFlight)
	}
	if got := total.Load(); got != parallelDialMaxIPs {
		t.Fatalf("total attempts %d, want %d", got, parallelDialMaxIPs)
	}
	if got := strings.Count(err.Error(), "refused"); got != parallelDialMaxIPs {
		t.Fatalf("joined errors %d, want %d", got, parallelDialMaxIPs)
	}
}

func TestBoundedParallelDialSmallSetAllAtOnce(t *testing.T) {
	ips := testIPs(parallelDialMaxInFlight)
	var started sync.WaitGroup
	started.Add(len(ips))
	allStarted := make(chan struct{})
	go func() { started.Wait(); close(allStarted) }()

	winner := newTrackingConn()
	dial := func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
		started.Done()
		select {
		case <-allStarted:
		case <-time.After(2 * time.Second):
			return nil, errors.New("attempts were not concurrent")
		}
		if ip == ips[len(ips)-1] {
			return winner, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}

	conn, err := boundedParallelDial(context.Background(), ips, dial)
	if err != nil {
		t.Fatal(err)
	}
	if conn != winner {
		t.Fatal("unexpected conn")
	}
	_ = conn.Close()
}

func TestBoundedParallelDialSuccessCancelsOthers(t *testing.T) {
	ips := testIPs(6)
	var losers sync.WaitGroup
	var cancelled atomic.Int32
	var lateConns []*closeTrackingConn
	var mu sync.Mutex
	winner := newTrackingConn()

	dial := func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
		if ip == ips[0] {
			time.Sleep(10 * time.Millisecond)
			return winner, nil
		}
		losers.Add(1)
		defer losers.Done()
		select {
		case <-ctx.Done():
			cancelled.Add(1)
			// a dial that completes despite the cancellation: must be closed
			c := newTrackingConn()
			mu.Lock()
			lateConns = append(lateConns, c)
			mu.Unlock()
			return c, nil
		case <-time.After(5 * time.Second):
			return nil, errors.New("not cancelled")
		}
	}

	conn, err := boundedParallelDial(context.Background(), ips, dial)
	if err != nil {
		t.Fatal(err)
	}
	if conn != winner {
		t.Fatal("unexpected conn")
	}
	defer conn.Close()

	done := make(chan struct{})
	go func() { losers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("losers were not cancelled")
	}
	// only the attempts already in flight ran; the rest never started
	if got := cancelled.Load(); got != parallelDialMaxInFlight-1 {
		t.Fatalf("cancelled losers %d, want %d", got, parallelDialMaxInFlight-1)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		allClosed := true
		for _, c := range lateConns {
			if !c.closed.Load() {
				allClosed = false
			}
		}
		mu.Unlock()
		if allClosed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("late loser connection not closed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if winner.closed.Load() {
		t.Fatal("winner closed")
	}
}

func TestBoundedParallelDialSingleAndEmpty(t *testing.T) {
	if _, err := boundedParallelDial(context.Background(), nil, nil); !errors.Is(err, ErrorNoIpAddress) {
		t.Fatalf("got %v", err)
	}
	c := newTrackingConn()
	conn, err := boundedParallelDial(context.Background(), testIPs(1), func(context.Context, netip.Addr) (net.Conn, error) {
		return c, nil
	})
	if err != nil || conn != c {
		t.Fatalf("got %v %v", conn, err)
	}
}

// The sequential path (tcp-concurrent off) is not capped: it still walks
// every address.
func TestSerialDialTriesEveryAddress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := serialDialContext(ctx, "tcp4", testIPs(20), "443", option{})
	if err == nil {
		t.Fatal("expected error")
	}
	if got := len(err.(interface{ Unwrap() []error }).Unwrap()); got != 20 {
		t.Fatalf("serial attempts %d, want 20", got)
	}
}
