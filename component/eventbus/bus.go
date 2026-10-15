// Package eventbus is an in-process publish/subscribe bus of core events
// (authentication, user limits, user changes, configuration reloads, provider
// updates, listener state, chain health) that the controller streams on GET /events.
//
// Publishing never blocks: every subscriber has a bounded buffer, and an
// event that does not fit is dropped for that subscriber and counted (see
// Subscription.TakeDropped). With nobody subscribed to a type, Enabled is a
// single atomic load and Publish returns at once, so the hooks in the core
// cost nothing while no one listens.
package eventbus

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Event types.
const (
	TypeAuth           = "auth"
	TypeUserLimit      = "user.limit"
	TypeUserChanged    = "user.changed"
	TypeConfigReload   = "config.reload"
	TypeProviderUpdate = "provider.update"
	TypeInboundState   = "inbound.state"
	TypeChainHealth    = "chain.health"
)

// TypeDropped is the type of the event a stream sends when events were
// dropped for it; it is not published on the bus and cannot be filtered out.
const TypeDropped = "dropped"

// Types lists the event types that can be subscribed to.
var Types = []string{TypeAuth, TypeUserLimit, TypeUserChanged, TypeConfigReload, TypeProviderUpdate, TypeInboundState, TypeChainHealth}

// Mask is a set of event types.
type Mask uint32

// All is every event type.
var All = func() Mask {
	var m Mask
	for i := range Types {
		m |= 1 << uint(i)
	}
	return m
}()

func bit(typ string) Mask {
	for i, t := range Types {
		if t == typ {
			return 1 << uint(i)
		}
	}
	return 0
}

// ErrUnknownType is returned by ParseTypes for a type that does not exist.
var ErrUnknownType = errors.New("unknown event type")

// ParseTypes parses a comma separated list of types; an empty list is All.
func ParseTypes(s string) (Mask, error) {
	var m Mask
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		b := bit(t)
		if b == 0 {
			return 0, errors.New(ErrUnknownType.Error() + ": " + t)
		}
		m |= b
	}
	if m == 0 {
		m = All
	}
	return m, nil
}

// Event is one event as it is streamed.
type Event struct {
	Type string    `json:"type"`
	Time time.Time `json:"time"`
	Data any       `json:"data,omitempty"`
}

// DefaultBuffer is the buffer of a subscriber of the controller stream.
const DefaultBuffer = 256

// Bus fans events out to its subscribers.
type Bus struct {
	mu     sync.RWMutex
	subs   map[*Subscription]struct{}
	active atomic.Uint32 // union of the masks of the subscribers

	published []atomic.Uint64 // by index of Types
	dropped   atomic.Uint64
}

// New returns an empty bus.
func New() *Bus {
	return &Bus{subs: make(map[*Subscription]struct{}), published: make([]atomic.Uint64, len(Types))}
}

// Subscription receives the events of the types of its mask.
type Subscription struct {
	bus     *Bus
	mask    Mask
	ch      chan Event
	dropped atomic.Uint64
	once    sync.Once
}

// C returns the channel of the events; it is closed by Close.
func (s *Subscription) C() <-chan Event { return s.ch }

// TakeDropped returns the number of events dropped for the subscriber since
// the previous call because its buffer was full.
func (s *Subscription) TakeDropped() uint64 { return s.dropped.Swap(0) }

// Close unsubscribes and closes the channel. It may be called more than once.
func (s *Subscription) Close() {
	s.once.Do(func() {
		b := s.bus
		b.mu.Lock()
		delete(b.subs, s)
		b.recomputeLocked()
		close(s.ch) // publishers send under the read lock
		b.mu.Unlock()
	})
}

func (b *Bus) recomputeLocked() {
	var m Mask
	for s := range b.subs {
		m |= s.mask
	}
	b.active.Store(uint32(m))
}

// Subscribe registers a subscriber of the types of mask with a buffer of
// size events.
func (b *Bus) Subscribe(mask Mask, size int) *Subscription {
	if size <= 0 {
		size = DefaultBuffer
	}
	s := &Subscription{bus: b, mask: mask & All, ch: make(chan Event, size)}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.recomputeLocked()
	b.mu.Unlock()
	return s
}

// Enabled reports whether anyone is subscribed to typ, so that a caller can
// skip building an event that nobody would receive.
func (b *Bus) Enabled(typ string) bool {
	return Mask(b.active.Load())&bit(typ) != 0
}

// Publish sends an event of typ with data to the subscribers of typ. It never
// blocks: a subscriber whose buffer is full misses the event.
func (b *Bus) Publish(typ string, data any) {
	m := bit(typ)
	if Mask(b.active.Load())&m == 0 {
		return
	}
	e := Event{Type: typ, Time: time.Now(), Data: data}
	b.mu.RLock()
	delivered := false
	for s := range b.subs {
		if s.mask&m == 0 {
			continue
		}
		select {
		case s.ch <- e:
			delivered = true
		default:
			s.dropped.Add(1)
			b.dropped.Add(1)
		}
	}
	b.mu.RUnlock()
	if delivered {
		for i, t := range Types {
			if t == typ {
				b.published[i].Add(1)
				break
			}
		}
	}
}

// Published returns the number of events of each type delivered to at least
// one subscriber since start, in the order of Types.
func (b *Bus) Published() []uint64 {
	out := make([]uint64, len(Types))
	for i := range out {
		out[i] = b.published[i].Load()
	}
	return out
}

// Dropped returns the number of events dropped for full subscriber buffers
// since start (an event dropped for two subscribers counts twice).
func (b *Bus) Dropped() uint64 { return b.dropped.Load() }

// Subscribers returns the number of subscribers.
func (b *Bus) Subscribers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

// Default is the bus of the core.
var Default = New()

// Enabled reports whether anyone is subscribed to typ on Default.
func Enabled(typ string) bool { return Default.Enabled(typ) }

// Publish publishes on Default.
func Publish(typ string, data any) { Default.Publish(typ, data) }

// Subscribe subscribes to Default.
func Subscribe(mask Mask, size int) *Subscription { return Default.Subscribe(mask, size) }
