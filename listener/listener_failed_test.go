package listener

import (
	"errors"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type fakeListener struct {
	name   string
	cfg    string // the configuration, the name when empty
	err    error
	listen int
	closed bool
}

func (f *fakeListener) Name() string            { return f.name }
func (f *fakeListener) Listen(C.Tunnel) error   { f.listen++; return f.err }
func (f *fakeListener) Close() error            { f.closed = true; return nil }
func (f *fakeListener) Address() string         { return "" }
func (f *fakeListener) RawAddress() string      { return "" }
func (f *fakeListener) Config() C.InboundConfig {
	if f.cfg != "" {
		return fakeConfig(f.cfg)
	}
	return fakeConfig(f.name)
}

type fakeConfig string

func (c fakeConfig) Name() string                 { return string(c) }
func (c fakeConfig) Equal(o C.InboundConfig) bool { return o.Name() == string(c) }

func TestFailedInboundListeners(t *testing.T) {
	t.Cleanup(func() { PatchInboundListeners(map[string]C.InboundListener{}, nil, true) })

	PatchInboundListeners(map[string]C.InboundListener{
		"bad":  &fakeListener{name: "bad", err: errors.New("address in use")},
		"good": &fakeListener{name: "good"},
	}, nil, true)
	if n := FailedInboundListeners(); n != 1 {
		t.Fatalf("failed listeners: got %d, want 1", n)
	}

	// the failing listener is removed from the configuration
	PatchInboundListeners(map[string]C.InboundListener{"good": &fakeListener{name: "good"}}, nil, true)
	if n := FailedInboundListeners(); n != 0 {
		t.Fatalf("failed listeners after removal: got %d, want 0", n)
	}

	// a listener that fails and then starts
	PatchInboundListeners(map[string]C.InboundListener{"flaky": &fakeListener{name: "flaky", err: errors.New("no cert")}}, nil, true)
	if n := FailedInboundListeners(); n != 1 {
		t.Fatalf("failed listeners: got %d, want 1", n)
	}
	PatchInboundListeners(map[string]C.InboundListener{"flaky": &fakeListener{name: "flaky"}}, nil, true)
	if n := FailedInboundListeners(); n != 0 {
		t.Fatalf("failed listeners after a successful start: got %d, want 0", n)
	}
}

// A reload whose new configuration fails to listen closes the old listener;
// reverting to the original configuration must start the inbound again.
func TestFailedReloadRevert(t *testing.T) {
	t.Cleanup(func() { PatchInboundListeners(map[string]C.InboundListener{}, nil, true) })

	a := &fakeListener{name: "in", cfg: "A"}
	PatchInboundListeners(map[string]C.InboundListener{"in": a}, nil, true)

	b := &fakeListener{name: "in", cfg: "B", err: errors.New("no cert")}
	PatchInboundListeners(map[string]C.InboundListener{"in": b}, nil, true)
	if !a.closed {
		t.Fatal("the old listener is not closed")
	}
	if n := FailedInboundListeners(); n != 1 {
		t.Fatalf("failed listeners: got %d, want 1", n)
	}
	if l, ok := GetInbound("in"); ok {
		t.Fatalf("the closed listener is still registered: %v", l)
	}

	a2 := &fakeListener{name: "in", cfg: "A"}
	PatchInboundListeners(map[string]C.InboundListener{"in": a2}, nil, true)
	if a2.listen != 1 {
		t.Fatalf("the reverted listener listened %d times, want 1", a2.listen)
	}
	if n := FailedInboundListeners(); n != 0 {
		t.Fatalf("failed listeners after the revert: got %d, want 0", n)
	}
	if l, _ := GetInbound("in"); l != a2 {
		t.Fatalf("registered listener: got %v, want the reverted one", l)
	}
}
