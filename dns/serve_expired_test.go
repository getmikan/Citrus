package dns

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

var (
	staleIP = netip.MustParseAddr("192.0.2.1")
	freshIP = netip.MustParseAddr("192.0.2.2")
)

// fakeUpstream answers A queries with freshIP after delay, or fails.
type fakeUpstream struct {
	delay time.Duration
	fail  atomic.Bool
	calls atomic.Int32
}

func (f *fakeUpstream) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	f.calls.Add(1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.fail.Load() {
		return nil, errors.New("upstream down")
	}
	return answerA(m, freshIP, 60), nil
}

func (f *fakeUpstream) Address() string  { return "fake" }
func (f *fakeUpstream) ResetConnection() {}

func answerA(query *D.Msg, ip netip.Addr, ttl uint32) *D.Msg {
	msg := new(D.Msg)
	msg.SetReply(query)
	msg.Answer = []D.RR{&D.A{
		Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: ttl},
		A:   ip.AsSlice(),
	}}
	return msg
}

func queryA() *D.Msg {
	m := new(D.Msg)
	m.SetQuestion("stale.example.", D.TypeA)
	return m
}

// newStaleResolver returns a resolver whose cache holds a staleIP answer that
// expired expiredFor ago.
func newStaleResolver(t *testing.T, up *fakeUpstream, serveExpired bool, ttl, clientTimeout, expiredFor time.Duration) *Resolver {
	t.Helper()
	r := &Resolver{
		main:                      []dnsClient{up},
		cache:                     Config{}.newCache(),
		serveExpired:              serveExpired,
		serveExpiredTTL:           ttl,
		serveExpiredClientTimeout: clientTimeout,
	}
	q := queryA()
	r.cache.SetWithExpire(q.Question[0].String(), answerA(q, staleIP, 60), time.Now().Add(-expiredFor))
	return r
}

func answerIP(t *testing.T, msg *D.Msg) netip.Addr {
	t.Helper()
	ips := msgToIP(msg)
	if len(ips) != 1 {
		t.Fatalf("expected one address, got %v", ips)
	}
	return ips[0]
}

func answerTTL(msg *D.Msg) uint32 {
	return msg.Answer[0].Header().Ttl
}

// waitRefreshed waits until the cache holds a non-expired freshIP answer.
func waitRefreshed(t *testing.T, r *Resolver) {
	t.Helper()
	key := cacheKey(queryA())
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		msg, expire, hit := getMsgFromCache(r.cache, key)
		if hit && expire.After(time.Now()) && msgToIP(msg)[0] == freshIP {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("cache was not refreshed in the background")
}

func TestServeExpiredDisabledResolvesAgain(t *testing.T) {
	up := &fakeUpstream{}
	r := newStaleResolver(t, up, false, 0, 0, time.Minute)

	msg, err := r.ExchangeContext(context.Background(), queryA())
	if err != nil {
		t.Fatal(err)
	}
	if ip := answerIP(t, msg); ip != freshIP {
		t.Fatalf("expected the fresh answer, got %s", ip)
	}
	if up.calls.Load() == 0 {
		t.Fatal("upstream was not queried")
	}
}

func TestServeExpiredDisabledDoesNotServeStaleOnFailure(t *testing.T) {
	up := &fakeUpstream{}
	up.fail.Store(true)
	r := newStaleResolver(t, up, false, 0, 0, time.Minute)

	if msg, err := r.ExchangeContext(context.Background(), queryA()); err == nil {
		t.Fatalf("expected an error without serve-expired, got %v", msg)
	}
}

func TestServeExpiredAnswersStaleAtOnceAndRefreshes(t *testing.T) {
	up := &fakeUpstream{delay: 200 * time.Millisecond}
	r := newStaleResolver(t, up, true, 0, 0, time.Hour)

	start := time.Now()
	msg, err := r.ExchangeContext(context.Background(), queryA())
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Fatalf("stale answer took %s, expected it at once", elapsed)
	}
	if ip := answerIP(t, msg); ip != staleIP {
		t.Fatalf("expected the stale answer, got %s", ip)
	}
	if ttl := answerTTL(msg); ttl != 1 {
		t.Fatalf("stale answer must carry TTL 1, got %d", ttl)
	}
	waitRefreshed(t, r)

	msg, err = r.ExchangeContext(context.Background(), queryA())
	if err != nil {
		t.Fatal(err)
	}
	if ip := answerIP(t, msg); ip != freshIP {
		t.Fatalf("expected the refreshed answer from cache, got %s", ip)
	}
}

func TestServeExpiredReturnsFreshWithinClientTimeout(t *testing.T) {
	up := &fakeUpstream{delay: 20 * time.Millisecond}
	r := newStaleResolver(t, up, true, 0, 2*time.Second, time.Minute)

	msg, err := r.ExchangeContext(context.Background(), queryA())
	if err != nil {
		t.Fatal(err)
	}
	if ip := answerIP(t, msg); ip != freshIP {
		t.Fatalf("expected the fresh answer within the client timeout, got %s", ip)
	}
}

func TestServeExpiredSlowUpstreamAnswersStaleAfterClientTimeout(t *testing.T) {
	up := &fakeUpstream{delay: time.Second}
	r := newStaleResolver(t, up, true, 0, 100*time.Millisecond, time.Minute)

	start := time.Now()
	msg, err := r.ExchangeContext(context.Background(), queryA())
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed < 100*time.Millisecond || elapsed > 800*time.Millisecond {
		t.Fatalf("expected the stale answer after the client timeout, took %s", elapsed)
	}
	if ip := answerIP(t, msg); ip != staleIP {
		t.Fatalf("expected the stale answer, got %s", ip)
	}
	waitRefreshed(t, r)
}

func TestServeExpiredUpstreamFailureAnswersStale(t *testing.T) {
	up := &fakeUpstream{}
	up.fail.Store(true)
	r := newStaleResolver(t, up, true, 0, 2*time.Second, time.Minute)

	start := time.Now()
	msg, err := r.ExchangeContext(context.Background(), queryA())
	if err != nil {
		t.Fatal(err)
	}
	if ip := answerIP(t, msg); ip != staleIP {
		t.Fatalf("expected the stale answer, got %s", ip)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a failed upstream must not hold the answer for the whole client timeout, took %s", elapsed)
	}
}

func TestServeExpiredCancelledClientAnswersStale(t *testing.T) {
	up := &fakeUpstream{delay: time.Second}
	r := newStaleResolver(t, up, true, 0, 2*time.Second, time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	msg, err := r.ExchangeContext(ctx, queryA())
	if err != nil {
		t.Fatal(err)
	}
	if ip := answerIP(t, msg); ip != staleIP {
		t.Fatalf("expected the stale answer, got %s", ip)
	}
}

func TestServeExpiredTTLLimit(t *testing.T) {
	up := &fakeUpstream{}
	up.fail.Store(true)
	// Expired two hours ago, but stale answers are allowed for one hour only.
	r := newStaleResolver(t, up, true, time.Hour, 0, 2*time.Hour)

	if msg, err := r.ExchangeContext(context.Background(), queryA()); err == nil {
		t.Fatalf("expected an error past serve-expired-ttl, got %v", msg)
	}

	up.fail.Store(false)
	msg, err := r.ExchangeContext(context.Background(), queryA())
	if err != nil {
		t.Fatal(err)
	}
	if ip := answerIP(t, msg); ip != freshIP {
		t.Fatalf("expected the fresh answer past serve-expired-ttl, got %s", ip)
	}
}

func TestServeExpiredFreshEntryUntouched(t *testing.T) {
	up := &fakeUpstream{}
	r := &Resolver{main: []dnsClient{up}, cache: Config{}.newCache(), serveExpired: true}
	q := queryA()
	r.cache.SetWithExpire(q.Question[0].String(), answerA(q, staleIP, 60), time.Now().Add(time.Minute))

	msg, err := r.ExchangeContext(context.Background(), queryA())
	if err != nil {
		t.Fatal(err)
	}
	if ip := answerIP(t, msg); ip != staleIP {
		t.Fatalf("expected the cached answer, got %s", ip)
	}
	if up.calls.Load() != 0 {
		t.Fatal("a fresh cache entry must not query the upstream")
	}
}
