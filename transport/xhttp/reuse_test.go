package xhttp

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
)

type testRoundTripper struct {
	id     int64
	closed atomic.Bool
}

func (t *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

func (t *testRoundTripper) Close() error {
	t.closed.Store(true)
	return nil
}

func roundTrip(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
}

func isClosed(rt *ReuseTransport) bool {
	return rt.entry.transport.(*testRoundTripper).closed.Load()
}

func makeTestTransportFactory(counter *atomic.Int64) TransportMaker {
	return func() http.RoundTripper {
		id := counter.Add(1)
		return &testRoundTripper{id: id}
	}
}

func transportID(rt *ReuseTransport) int64 {
	return rt.entry.transport.(*testRoundTripper).id
}

func TestManagerReuseSameEntry(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConcurrency:   "1",
		MaxConnections:   "1",
		HMaxRequestTimes: "10",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}

	transport1 := manager.GetTransport().(*ReuseTransport)
	id1 := transportID(transport1)

	transport1.Close()

	transport2 := manager.GetTransport().(*ReuseTransport)
	id2 := transportID(transport2)

	if id1 != id2 {
		t.Fatalf("expected same transport to be reused, got %d and %d", id1, id2)
	}

	transport2.Close()
	manager.Close()
}

func TestManagerRespectMaxConnections(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConcurrency:   "2",
		MaxConnections:   "2",
		HMaxRequestTimes: "100",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}

	transport1 := manager.GetTransport().(*ReuseTransport)
	id1 := transportID(transport1)
	transport2 := manager.GetTransport().(*ReuseTransport)
	id2 := transportID(transport2)
	transport3 := manager.GetTransport().(*ReuseTransport)
	id3 := transportID(transport3)
	transport4 := manager.GetTransport().(*ReuseTransport)
	id4 := transportID(transport4)
	transport5 := manager.GetTransport().(*ReuseTransport)
	id5 := transportID(transport5)

	if id1 == id2 {
		t.Fatal("expected the second transport to be new")
	}

	if id3 != id1 && id3 != id2 {
		t.Fatal("expected the third transport to be reused")
	}

	if id4 != id1 && id4 != id2 {
		t.Fatal("expected the fourth transport to be reused")
	}

	if id5 == id1 || id5 == id2 {
		t.Fatal("expected the fifth transport to be new")
	}

	transport1.Close()
	transport2.Close()
	transport3.Close()
	transport4.Close()
	transport5.Close()
	manager.Close()
}

func TestManagerRotateOnRequestLimit(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConcurrency:   "1",
		MaxConnections:   "1",
		HMaxRequestTimes: "1",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}

	transport1 := manager.GetTransport().(*ReuseTransport)
	id1 := transportID(transport1)
	roundTrip(t, transport1)

	transport1.Close()

	transport2 := manager.GetTransport().(*ReuseTransport)
	id2 := transportID(transport2)

	if id1 == id2 {
		t.Fatalf("expected new transport after request limit, got same id %d", id1)
	}

	transport2.Close()
	manager.Close()
}

func TestManagerRotateOnReusableSecs(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConcurrency:   "1",
		MaxConnections:   "1",
		HMaxRequestTimes: "100",
		HMaxReusableSecs: "1",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}

	transport1 := manager.GetTransport().(*ReuseTransport)
	id1 := transportID(transport1)

	time.Sleep(1100 * time.Millisecond)
	transport1.Close()

	transport2 := manager.GetTransport().(*ReuseTransport)
	id2 := transportID(transport2)

	if id1 == id2 {
		t.Fatalf("expected new transport after reusable timeout, got same id %d", id1)
	}

	transport2.Close()
	manager.Close()
}

func TestManagerRotateOnConnReuseLimit(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConcurrency:   "1",
		MaxConnections:   "1",
		CMaxReuseTimes:   "1",
		HMaxRequestTimes: "100",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}

	transport1 := manager.GetTransport().(*ReuseTransport)
	id1 := transportID(transport1)

	transport1.Close()

	transport2 := manager.GetTransport().(*ReuseTransport)
	id2 := transportID(transport2)

	if id1 != id2 {
		t.Fatalf("expected first reuse to use same transport, got %d and %d", id1, id2)
	}

	transport2.Close()

	transport3 := manager.GetTransport().(*ReuseTransport)
	id3 := transportID(transport3)

	if id3 == id2 {
		t.Fatalf("expected new transport after c-max-reuse-times limit, got same id %d", id3)
	}

	transport3.Close()
	manager.Close()
}

// hMaxRequestTimes counts HTTP requests (like Xray-core), not proxied connections.
func TestManagerCountRequestsNotConnections(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConnections:   "1",
		HMaxRequestTimes: "3",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	// dials alone don't use up the requests
	for i := 0; i < 5; i++ {
		rt := manager.GetTransport().(*ReuseTransport)
		if id := transportID(rt); id != 1 {
			t.Fatalf("expected the first transport to be reused, got %d", id)
		}
		rt.Close()
	}

	transport1 := manager.GetTransport().(*ReuseTransport)
	roundTrip(t, transport1)
	roundTrip(t, transport1)
	transport2 := manager.GetTransport().(*ReuseTransport)
	if transportID(transport2) != 1 {
		t.Fatal("expected the transport to be reused before the request limit")
	}
	roundTrip(t, transport2) // the third request retires the entry

	transport3 := manager.GetTransport().(*ReuseTransport)
	if transportID(transport3) == 1 {
		t.Fatal("expected a new transport after the request limit")
	}

	// the retired entry keeps serving the connections that hold it, and is closed with the last one
	roundTrip(t, transport1)
	transport1.Close()
	if isClosed(transport2) {
		t.Fatal("retired transport closed while still in use")
	}
	transport2.Close()
	if !isClosed(transport2) {
		t.Fatal("retired transport not closed after the last user")
	}
	transport3.Close()
	if isClosed(transport3) {
		t.Fatal("idle transport closed before it is retired")
	}
}

// An entry past hMaxReusableSecs is not handed out, even while other connections still hold it.
func TestManagerSkipExpiredInUse(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(&ReuseConfig{
		MaxConnections:   "1",
		HMaxReusableSecs: "1",
	}, makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	transport1 := manager.GetTransport().(*ReuseTransport)
	transport1.entry.unreusableAt = time.Now().Add(-time.Second)

	transport2 := manager.GetTransport().(*ReuseTransport)
	if transportID(transport2) == transportID(transport1) {
		t.Fatal("expected a new transport after the entry expired")
	}
	if isClosed(transport1) {
		t.Fatal("expired transport closed while still in use")
	}
	transport1.Close()
	if !isClosed(transport1) {
		t.Fatal("expired transport not closed after the last user")
	}
	transport2.Close()
}

// The default XMUX (no maxConcurrency) shares maxConnections transports among any number of connections.
func TestManagerDefaultReuseConfig(t *testing.T) {
	var created atomic.Int64

	manager, err := NewReuseManager(DefaultReuseConfig(), makeTestTransportFactory(&created))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	var transports []*ReuseTransport
	for i := 0; i < 30; i++ {
		transports = append(transports, manager.GetTransport().(*ReuseTransport))
	}
	if created.Load() != 3 {
		t.Fatalf("expected 3 transports, got %d", created.Load())
	}
	for _, rt := range transports {
		rt.Close()
	}
}
