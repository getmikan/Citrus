// Package authevent reports rejected authentication attempts on inbound
// listeners to an embedder, for example to feed fail2ban-like blocking or a
// panel's audit log.
//
// Events carry bounded metadata only: the protocol, the listener and client
// addresses, a reason from the Reason constants and, for HTTP-based protocols,
// the request method. Credentials, URLs, headers and payloads are never
// included.
//
// The handler is process-global. Emit never blocks the handshake goroutine
// that calls it: events go through a bounded queue to a single dispatcher
// goroutine, and are dropped (and counted, see Dropped) when the queue is
// full. With no handler set, Emit is a single atomic load (two with the
// tap of the event stream installed, see SetTap).
//
// Ported from Kinkan (GetsuNoKaze/kinkan), patches/mihomo/0002-auth-events.patch.
package authevent

import (
	"net"
	"sync/atomic"
)

// Event describes one rejected authentication attempt.
type Event struct {
	Protocol string // inbound protocol, e.g. "trusttunnel", "vless"
	Local    string // listener address the attempt arrived on, if known
	Remote   string // client address
	Reason   string // one of the Reason constants
	Method   string // HTTP method, for HTTP-based protocols only
}

// Reasons reported in Event.Reason.
const (
	// ReasonNoCredentials: the client presented no credentials at all.
	ReasonNoCredentials = "no_credentials"
	// ReasonWrongCredentials: the credentials did not match any user.
	ReasonWrongCredentials = "wrong_credentials"
	// ReasonRejectedHandshake: the handshake failed before credentials could
	// be told apart from noise (REALITY, Sudoku).
	ReasonRejectedHandshake = "rejected_handshake"
	// ReasonAuthenticationTimeout: the client did not authenticate in time.
	ReasonAuthenticationTimeout = "authentication_timeout"
)

// QueueSize is the number of events that may wait for the handler before new
// ones are dropped.
const QueueSize = 1024

type sink struct {
	fn    func(Event)
	queue chan Event
	stop  chan struct{}
}

var (
	current atomic.Pointer[sink]
	dropped atomic.Uint64
	tap     atomic.Pointer[tapFuncs]
)

type tapFuncs struct {
	enabled func() bool
	fn      func(Event)
}

// SetTap installs an observer next to the handler, for the core's own event
// stream: fn is called by Emit, on the caller's goroutine, while enabled
// reports true, so it must not block. nil fn removes it. Unlike the handler,
// the tap does not replace or get replaced by SetHandler.
func SetTap(enabled func() bool, fn func(Event)) {
	if fn == nil || enabled == nil {
		tap.Store(nil)
		return
	}
	tap.Store(&tapFuncs{enabled: enabled, fn: fn})
}

func tapOn() *tapFuncs {
	if t := tap.Load(); t != nil && t.enabled() {
		return t
	}
	return nil
}

// SetHandler installs fn as the handler, replacing the previous one; nil
// removes it. fn runs on a dedicated goroutine, one event at a time. Events
// still queued for a replaced handler are discarded. A panic in fn is
// recovered and the event is lost.
func SetHandler(fn func(Event)) {
	var next *sink
	if fn != nil {
		next = &sink{fn: fn, queue: make(chan Event, QueueSize), stop: make(chan struct{})}
		go next.run()
	}
	if prev := current.Swap(next); prev != nil {
		close(prev.stop)
	}
}

// Enabled reports whether a handler is set or the tap wants events, so a
// caller can skip building an event that nobody would receive.
func Enabled() bool {
	return current.Load() != nil || tapOn() != nil
}

// Emit queues e for the handler. It never blocks; with no handler set it
// returns at once.
func Emit(e Event) {
	if t := tapOn(); t != nil {
		t.fn(e)
	}
	s := current.Load()
	if s == nil {
		return
	}
	select {
	case s.queue <- e:
	default:
		dropped.Add(1)
	}
}

// EmitAddr is Emit for connection-based protocols. The addresses are only
// formatted when a handler is set.
func EmitAddr(protocol, reason string, local, remote net.Addr) {
	if !Enabled() {
		return
	}
	Emit(Event{Protocol: protocol, Local: addrString(local), Remote: addrString(remote), Reason: reason})
}

// Dropped returns the number of events lost because the queue was full.
func Dropped() uint64 {
	return dropped.Load()
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func (s *sink) run() {
	for {
		select {
		case <-s.stop:
			return
		case e := <-s.queue:
			s.call(e)
		}
	}
}

func (s *sink) call(e Event) {
	defer func() { _ = recover() }()
	s.fn(e)
}
