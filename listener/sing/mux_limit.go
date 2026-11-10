package sing

import (
	"context"
	"errors"
	"math"
	"net"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"

	L "github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
)

// DefaultMuxMaxStreams caps the sub-streams (TCP and UDP) one sing-mux
// connection (smux, yamux or h2mux) may have open at once; a sub-stream beyond
// it is closed as soon as it is accepted, and the connection and its other
// sub-streams keep working. Every sub-stream costs a goroutine and buffers, so
// without a cap one client could open sub-streams until the process runs out
// of memory. 1024 matches the Trojan and AnyTLS mux caps and is far above what
// one client multiplexes (a phone with a few hundred connections). The
// mux-option max-streams of an inbound overrides it.
const DefaultMuxMaxStreams = 1024

const (
	// muxStreamRequestTimeout bounds the wait for the request header of a
	// sub-stream: sing-mux reads it before Citrus sees the sub-stream, so a
	// sub-stream that never sends one would otherwise hold its slot (and a
	// goroutine) for the life of the connection. Clients send the header at
	// once (mihomo when it dials, sing-box within its 300ms payload wait).
	muxStreamRequestTimeout = 15 * time.Second
	// muxStreamReleaseGrace is how long after muxStreamRequestTimeout a slot
	// whose sub-stream never reached the handler (its header failed, timed
	// out, or was a TCP Brutal exchange) is given back.
	muxStreamReleaseGrace = 5 * time.Second
)

var errMuxStreamLimit = errors.New("too many mux sub-streams")

// muxStreams counts the open sub-streams of one sing-mux connection. A nested
// sing-mux connection inside a sub-stream shares the counter of its parent, so
// nesting cannot multiply the cap.
type muxStreams struct {
	max    int32
	source M.Socksaddr
	open   atomic.Int32

	// refusals are logged at most once a second per connection
	lastLog    atomic.Int64 // unix nanoseconds
	suppressed atomic.Int64
}

func (m *muxStreams) acquire() bool {
	for {
		n := m.open.Load()
		if n >= m.max {
			return false
		}
		if m.open.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (m *muxStreams) release() { m.open.Add(-1) }

func (m *muxStreams) logRefused() {
	now := time.Now().UnixNano()
	last := m.lastLog.Load()
	if now-last < int64(time.Second) || !m.lastLog.CompareAndSwap(last, now) {
		m.suppressed.Add(1)
		return
	}
	suppressed := m.suppressed.Swap(0)
	if suppressed > 0 {
		log.Warnln("[Mux] %s: sub-stream refused, %d open is the limit (and %d more refused since the last line)", m.source, m.max, suppressed)
	} else {
		log.Warnln("[Mux] %s: sub-stream refused, %d open is the limit", m.source, m.max)
	}
}

// states of a muxStream
const (
	muxStreamPending int32 = iota // accepted, its header not read yet
	muxStreamHandled              // in the handler, which releases the slot
	muxStreamExpired              // the slot was given back by the timer
	muxStreamRefused              // over the cap, closed when accepted
)

// muxStream is one accepted sub-stream; it holds a slot of its connection
// from its acceptance until the handler returns or, if the sub-stream never
// reaches the handler, until the release timer fires.
type muxStream struct {
	streams *muxStreams
	conn    net.Conn
	state   atomic.Int32
	timer   *time.Timer
}

func (s *muxStream) expire() {
	if s.state.CompareAndSwap(muxStreamPending, muxStreamExpired) {
		s.streams.release()
		// close it too: an h2mux stream takes no read deadline, and its
		// goroutine would otherwise wait for a header until the session ends
		_ = s.conn.Close()
	}
}

type muxStreamsKey struct{}
type muxStreamKey struct{}

// withMuxStreams returns ctx carrying the sub-stream counter of a new sing-mux
// connection; a nested one keeps the counter of its parent.
func withMuxStreams(ctx context.Context, max int, source M.Socksaddr) context.Context {
	if _, ok := ctx.Value(muxStreamsKey{}).(*muxStreams); ok {
		return ctx
	}
	if max <= 0 {
		max = DefaultMuxMaxStreams
	}
	if max > math.MaxInt32 {
		max = math.MaxInt32
	}
	return context.WithValue(ctx, muxStreamsKey{}, &muxStreams{max: int32(max), source: source})
}

// newMuxStreamContext is the NewStreamContext of the sing-mux service: it runs
// in the accept loop of the connection for each sub-stream, before sing-mux
// starts the goroutine of the sub-stream.
func (h *ListenerHandler) newMuxStreamContext(ctx context.Context, conn net.Conn) context.Context {
	streams, ok := ctx.Value(muxStreamsKey{}).(*muxStreams)
	if !ok {
		return ctx
	}
	s := &muxStream{streams: streams, conn: conn}
	if !streams.acquire() {
		s.state.Store(muxStreamRefused)
		streams.logRefused()
		// the client sees the sub-stream closed; not in the accept loop, as an
		// smux Close may wait for a client that stopped reading
		go conn.Close()
		return context.WithValue(ctx, muxStreamKey{}, s)
	}
	// h2mux streams have no read deadline; http2 caps them at 250 per
	// connection anyway
	_ = conn.SetReadDeadline(time.Now().Add(h.muxRequestTimeout))
	s.timer = time.AfterFunc(h.muxRequestTimeout+h.muxReleaseGrace, s.expire)
	return context.WithValue(ctx, muxStreamKey{}, s)
}

func noRelease() {}

// enterMuxStream is called when a sub-stream reaches the handler. It returns
// the function that gives the slot back, to be deferred, or errMuxStreamLimit
// when the sub-stream must be refused. It does nothing outside sing-mux, and
// for a nested call (UoT in a sub-stream), whose slot is already held.
func enterMuxStream(ctx context.Context) (func(), error) {
	s, ok := ctx.Value(muxStreamKey{}).(*muxStream)
	if !ok {
		return noRelease, nil
	}
	if s.state.CompareAndSwap(muxStreamPending, muxStreamHandled) {
		s.timer.Stop()
		_ = s.conn.SetReadDeadline(time.Time{})
		return s.streams.release, nil
	}
	switch s.state.Load() {
	case muxStreamHandled:
		return noRelease, nil
	case muxStreamExpired:
		// the header came just as the timer gave the slot back (only the
		// handler leaves this state)
		if s.streams.acquire() {
			s.state.Store(muxStreamHandled)
			_ = s.conn.SetReadDeadline(time.Time{})
			return s.streams.release, nil
		}
		s.streams.logRefused()
	}
	return nil, errMuxStreamLimit
}

// muxLogger is the logger of the sing-mux service. sing-mux logs an error only
// for a sub-stream that never reached the handler (its header could not be
// read, or a TCP Brutal exchange failed): one client's sub-stream, so it is
// logged at debug level, as a client could otherwise flood the log with
// silent sub-streams. The error of a sub-stream refused over the cap (its
// header cannot be read from the closed sub-stream) is dropped: refusals are
// logged, rate-limited, by muxStreams.
type muxLogger struct {
	L.ContextLogger
}

func (l muxLogger) ErrorContext(ctx context.Context, args ...any) {
	if s, ok := ctx.Value(muxStreamKey{}).(*muxStream); ok && s.state.Load() == muxStreamRefused {
		return
	}
	l.ContextLogger.DebugContext(ctx, args...)
}
