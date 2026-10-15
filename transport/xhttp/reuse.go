package xhttp

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/httputils"

	"github.com/metacubex/http"
)

// reuseEntry is one shared HTTP client (aka XmuxClient in Xray-core): a transport that
// several proxied connections send their requests through.
type reuseEntry struct {
	transport http.RoundTripper

	openUsage     atomic.Int32 // proxied connections that hold the entry
	leftRequests  atomic.Int32 // HTTP requests left before the entry is retired (hMaxRequestTimes)
	reuseCount    atomic.Int32
	maxReuseTimes int32
	unreusableAt  time.Time

	closed atomic.Bool
}

func (entry *reuseEntry) isClosed() bool {
	return entry.closed.Load()
}

func (entry *reuseEntry) close() {
	if !entry.closed.CompareAndSwap(false, true) {
		return
	}
	httputils.CloseTransport(entry.transport)
}

// retired reports whether the entry must not be handed to new proxied connections anymore.
// A retired entry keeps serving the connections that already hold it and is closed with the last one.
func (entry *reuseEntry) retired(now time.Time) bool {
	return entry.isClosed() ||
		entry.leftRequests.Load() <= 0 ||
		(entry.maxReuseTimes > 0 && entry.reuseCount.Load() >= entry.maxReuseTimes) ||
		(!entry.unreusableAt.IsZero() && now.After(entry.unreusableAt))
}

type ReuseTransport struct {
	manager *ReuseManager
	entry   *reuseEntry
	removed atomic.Bool
}

// RoundTrip sends the request through the shared transport.
// Like Xray-core, hMaxRequestTimes counts HTTP requests, not proxied connections:
// a packet-up connection sends many requests through the same entry.
func (rt *ReuseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.entry.leftRequests.Add(-1)
	return rt.entry.transport.RoundTrip(req)
}

func (rt *ReuseTransport) Close() error {
	if !rt.removed.CompareAndSwap(false, true) {
		return nil
	}
	rt.manager.release(rt.entry)
	return nil
}

var _ http.RoundTripper = (*ReuseTransport)(nil)

type ReuseManager struct {
	maxConcurrency   int
	maxConnections   int
	cMaxReuseTimes   Range
	hMaxRequestTimes Range
	hMaxReusableSecs Range
	maker            TransportMaker
	mu               sync.Mutex
	entries          []*reuseEntry
}

func NewReuseManager(cfg *ReuseConfig, makeTransport TransportMaker) (*ReuseManager, error) {
	if cfg == nil {
		return nil, nil
	}
	concurrency, connections, err := cfg.ResolveManagerConfig()
	if err != nil {
		return nil, err
	}
	cMaxReuseTimes, hMaxRequestTimes, hMaxReusableSecs, err := cfg.ResolveEntryConfig()
	if err != nil {
		return nil, err
	}
	return &ReuseManager{
		maxConcurrency:   concurrency.Rand(),
		maxConnections:   connections.Rand(),
		cMaxReuseTimes:   cMaxReuseTimes,
		hMaxRequestTimes: hMaxRequestTimes,
		hMaxReusableSecs: hMaxReusableSecs,
		maker:            makeTransport,
		entries:          make([]*reuseEntry, 0),
	}, nil
}

func (m *ReuseManager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, entry := range m.entries {
		entry.close()
	}
	m.entries = nil
	return nil
}

// cleanupLocked drops the retired entries from the pool, so they are no longer counted against maxConnections,
// and closes the ones that no proxied connection holds anymore.
func (m *ReuseManager) cleanupLocked(now time.Time) {
	kept := m.entries[:0]
	for _, entry := range m.entries {
		if entry.retired(now) {
			if entry.openUsage.Load() == 0 {
				entry.close()
			}
			continue
		}
		kept = append(kept, entry)
	}
	for i := len(kept); i < len(m.entries); i++ {
		m.entries[i] = nil // don't keep the dropped entries alive
	}
	m.entries = kept
}

// release is called when a proxied connection stops using the entry.
// It runs under the manager lock, so an entry can't be handed out by GetTransport while it is being closed.
func (m *ReuseManager) release(entry *reuseEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry.openUsage.Add(-1) > 0 {
		return
	}
	entry.openUsage.Store(0)
	if entry.retired(time.Now()) {
		entry.close()
	}
}

func (m *ReuseManager) pickLocked() *reuseEntry {
	var best *reuseEntry
	for _, entry := range m.entries {
		if m.maxConcurrency > 0 && int(entry.openUsage.Load()) >= m.maxConcurrency {
			continue
		}
		if best == nil || entry.openUsage.Load() < best.openUsage.Load() {
			best = entry
		}
	}
	return best
}

func (m *ReuseManager) shouldCreateLocked() bool {
	if len(m.entries) == 0 {
		return true
	}
	if m.maxConnections > 0 {
		return len(m.entries) < m.maxConnections
	}
	return false
}

func (m *ReuseManager) newEntryLocked(transport http.RoundTripper, now time.Time) *reuseEntry {
	entry := &reuseEntry{transport: transport}

	if m.hMaxRequestTimes.Max > 0 {
		entry.leftRequests.Store(int32(m.hMaxRequestTimes.Rand()))
	} else {
		entry.leftRequests.Store(1<<30 - 1)
	}
	if m.hMaxReusableSecs.Max > 0 {
		entry.unreusableAt = now.Add(time.Duration(m.hMaxReusableSecs.Rand()) * time.Second)
	}
	if m.cMaxReuseTimes.Max > 0 {
		entry.maxReuseTimes = int32(m.cMaxReuseTimes.Rand())
	}

	m.entries = append(m.entries, entry)
	return entry
}

func (m *ReuseManager) GetTransport() http.RoundTripper {
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.cleanupLocked(now)

	var entry *reuseEntry
	if !m.shouldCreateLocked() {
		entry = m.pickLocked()
	}

	if entry == nil {
		entry = m.newEntryLocked(m.maker(), now)
	} else {
		entry.reuseCount.Add(1)
	}
	entry.openUsage.Add(1)

	return &ReuseTransport{manager: m, entry: entry}
}
