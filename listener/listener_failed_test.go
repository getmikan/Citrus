package listener

import (
	"errors"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type fakeListener struct {
	name string
	err  error
}

func (f *fakeListener) Name() string            { return f.name }
func (f *fakeListener) Listen(C.Tunnel) error   { return f.err }
func (f *fakeListener) Close() error            { return nil }
func (f *fakeListener) Address() string         { return "" }
func (f *fakeListener) RawAddress() string      { return "" }
func (f *fakeListener) Config() C.InboundConfig { return fakeConfig(f.name) }

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
