package statistic

import (
	"sort"
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
)

// Counters read by the Prometheus endpoint (GET /metrics).
//
// The global totals and the per-user counters already exist for the REST API;
// what /metrics needs on top of them is the number of connections ever opened
// and the per-inbound counters. The per-inbound counters cost one atomic add
// per read or write of a connection of a named inbound, so they are only bound
// to connections opened while the metrics are enabled (SetInboundStatsEnabled).

var inboundStatsEnabled atomic.Bool

// SetInboundStatsEnabled turns the per-inbound accounting on or off (it follows
// `metrics.enable`). Connections opened while it is off are not counted per
// inbound; the counters already collected are kept.
func SetInboundStatsEnabled(enabled bool) { inboundStatsEnabled.Store(enabled) }

// InboundCounter holds the cumulative traffic and the open connections of an
// inbound (metadata.InName).
type InboundCounter struct {
	up    atomic.Int64
	_     [cacheLinePad]byte
	down  atomic.Int64
	_     [cacheLinePad]byte
	conns atomic.Int64
}

func (c *InboundCounter) addUp(n int64) {
	if c != nil {
		c.up.Add(n)
	}
}

func (c *InboundCounter) addDown(n int64) {
	if c != nil {
		c.down.Add(n)
	}
}

func (c *InboundCounter) release() {
	if c != nil {
		c.conns.Add(-1)
	}
}

// InboundStat is a snapshot of an inbound's counters.
type InboundStat struct {
	Inbound string
	Up      int64
	Down    int64
	Conns   int64
}

// bindInbound returns the counter of the inbound of metadata with a new
// connection registered on it, or nil when the connection is not counted.
func (m *Manager) bindInbound(metadata *C.Metadata, pushToManager bool) *InboundCounter {
	if !pushToManager || metadata == nil || metadata.InName == "" || !inboundStatsEnabled.Load() {
		return nil
	}
	c, ok := m.inbounds.Load(metadata.InName)
	if !ok {
		c, _ = m.inbounds.LoadOrStore(metadata.InName, &InboundCounter{})
	}
	c.conns.Add(1)
	return c
}

// Inbounds returns the counters of every inbound that carried a connection
// while the per-inbound accounting was on, sorted by name.
func (m *Manager) Inbounds() []InboundStat {
	stats := make([]InboundStat, 0)
	m.inbounds.Range(func(name string, c *InboundCounter) bool {
		stats = append(stats, InboundStat{Inbound: name, Up: c.up.Load(), Down: c.down.Load(), Conns: c.conns.Load()})
		return true
	})
	sort.Slice(stats, func(i, j int) bool { return stats[i].Inbound < stats[j].Inbound })
	return stats
}

// ConnectionCount returns the number of tracked open connections.
func (m *Manager) ConnectionCount() int { return m.connections.Size() }

// ConnectionsOpened returns the number of connections tracked since start.
func (m *Manager) ConnectionsOpened() int64 { return m.opened.Load() }

// UserMetric is what /metrics reports of a user: the cumulative counters
// (never affected by a drain), the open connections, the online addresses
// (open, or closed within the release window, as max-ips counts them) and the
// rejections by reason.
type UserMetric struct {
	Key       UserKey
	Up        int64
	Down      int64
	Conns     int64
	OnlineIPs int64
	Rejected  map[string]int64
}

// Metrics returns a UserMetric of every user, sorted by inbound and user. It
// is lighter than Snapshot: no address list is built.
func (um *UserManager) Metrics() []UserMetric {
	now := um.now()
	out := make([]UserMetric, 0, um.counters.Size())
	um.counters.Range(func(key UserKey, c *UserCounter) bool {
		c.mu.Lock()
		if !c.deleted {
			m := UserMetric{Key: key, Up: c.up.Load(), Down: c.down.Load(), Conns: c.conns.Load()}
			for _, e := range c.ips {
				if e.conns > 0 || now.Sub(e.lastSeen) <= um.IPRelease {
					m.OnlineIPs++
				}
			}
			if len(c.reasons) > 0 {
				m.Rejected = make(map[string]int64, len(c.reasons))
				for k, v := range c.reasons {
					m.Rejected[k] = v
				}
			}
			out = append(out, m)
		}
		c.mu.Unlock()
		return true
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key.Inbound != out[j].Key.Inbound {
			return out[i].Key.Inbound < out[j].Key.Inbound
		}
		return out[i].Key.User < out[j].Key.User
	})
	return out
}
