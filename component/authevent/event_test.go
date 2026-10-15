package authevent

import (
	"net"
	"testing"
	"time"
)

func collect(t *testing.T, size int) <-chan Event {
	t.Helper()
	events := make(chan Event, size)
	SetHandler(func(e Event) { events <- e })
	t.Cleanup(func() { SetHandler(nil) })
	return events
}

func receive(t *testing.T, events <-chan Event) Event {
	t.Helper()
	select {
	case e := <-events:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no event delivered")
		return Event{}
	}
}

func TestEmitWithoutHandler(t *testing.T) {
	SetHandler(nil)
	if Enabled() {
		t.Fatal("Enabled with no handler")
	}
	Emit(Event{Protocol: "test"})
	EmitAddr("test", ReasonWrongCredentials, nil, nil)
}

func TestEmitDelivers(t *testing.T) {
	events := collect(t, 1)
	if !Enabled() {
		t.Fatal("not Enabled with a handler")
	}
	want := Event{Protocol: "test", Local: "1.1.1.1:443", Remote: "2.2.2.2:5000", Reason: ReasonNoCredentials, Method: "CONNECT"}
	Emit(want)
	if got := receive(t, events); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestEmitAddr(t *testing.T) {
	events := collect(t, 1)
	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	EmitAddr("test", ReasonWrongCredentials, local, nil)
	got := receive(t, events)
	want := Event{Protocol: "test", Local: "127.0.0.1:443", Reason: ReasonWrongCredentials}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestEmitDoesNotBlock(t *testing.T) {
	release := make(chan struct{})
	SetHandler(func(Event) { <-release })
	t.Cleanup(func() {
		close(release)
		SetHandler(nil)
	})
	before := Dropped()
	done := make(chan struct{})
	go func() {
		// The handler holds one event, the queue the next QueueSize.
		for i := 0; i < QueueSize+10; i++ {
			Emit(Event{Protocol: "test"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Emit blocked on a slow handler")
	}
	if Dropped() == before {
		t.Fatal("overflow was not counted as dropped")
	}
}

func TestHandlerPanicIsRecovered(t *testing.T) {
	events := make(chan Event, 1)
	SetHandler(func(e Event) {
		if e.Protocol == "panic" {
			panic("handler")
		}
		events <- e
	})
	t.Cleanup(func() { SetHandler(nil) })
	Emit(Event{Protocol: "panic"})
	Emit(Event{Protocol: "after"})
	if got := receive(t, events); got.Protocol != "after" {
		t.Fatalf("got %+v after a panicking event", got)
	}
}

func TestSetHandlerReplaces(t *testing.T) {
	first := make(chan Event, 1)
	SetHandler(func(e Event) { first <- e })
	second := collect(t, 1)
	Emit(Event{Protocol: "test"})
	receive(t, second)
	select {
	case e := <-first:
		t.Fatalf("replaced handler received %+v", e)
	default:
	}
}

func BenchmarkEmitDisabled(b *testing.B) {
	SetHandler(nil)
	e := Event{Protocol: "test", Reason: ReasonWrongCredentials}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Emit(e)
	}
}
