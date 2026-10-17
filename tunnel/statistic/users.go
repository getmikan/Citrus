package statistic

import (
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/eventbus"
	C "github.com/metacubex/mihomo/constant"
)

// Per-user traffic accounting.
//
// Every connection that the tunnel carries for an authenticated inbound user
// (metadata.InUser is not empty) adds its payload bytes to the counter of the
// pair (inbound name, user). The bytes are counted on the outbound side of the
// tunnel, exactly like the global totals and the per-connection counters: they
// are the bytes the user exchanged with the destinations, without the overhead
// of the inbound protocol (TLS, VLESS/Trojan headers, mux frames and so on).
//
// The counter is resolved once per connection (TCP) or per NAT session (UDP);
// the hot path is one atomic add per read or write. Connections without a user
// (TUN, redir, anonymous inbounds) cost a nil check.

const (
	defaultUserIdleTTL   = 10 * time.Minute
	defaultUserIPRelease = time.Minute
	userSweepInterval    = time.Minute
)

var userStatsEnabled atomic.Bool

func init() {
	userStatsEnabled.Store(true)
}

// SetUserStatsEnabled turns the per-user accounting on or off (the
// `user-stats` option). Connections opened while it is off are not attributed;
// the counters already collected are kept.
func SetUserStatsEnabled(enabled bool) { userStatsEnabled.Store(enabled) }

// UserStatsEnabled reports whether new connections are attributed to users.
func UserStatsEnabled() bool { return userStatsEnabled.Load() }

// UserKey identifies a user of an inbound: metadata.InName and metadata.InUser.
type UserKey struct {
	Inbound string
	User    string
}

// UserIP is a source address of a user with the number of its open
// connections. An address stays listed for a short release window after its
// last connection is closed.
type UserIP struct {
	IP       netip.Addr `json:"ip"`
	Conns    int64      `json:"conns"`
	LastSeen time.Time  `json:"lastSeen"`
}

// UserStat is a snapshot of a user's counters. Up and Down are cumulative
// since the counter was created in Snapshot and Get, and the bytes since the
// previous drain in Drain.
type UserStat struct {
	Inbound    string    `json:"inbound"`
	User       string    `json:"user"`
	Up         int64     `json:"up"`
	Down       int64     `json:"down"`
	Conns      int64     `json:"conns"`
	IPs        []UserIP  `json:"ips"`
	LastActive time.Time `json:"lastActive"`
	// Rejected is the number of connections refused by the user's limits,
	// RejectReasons the same by reason (expired, quota, max-conns, max-ips).
	Rejected      int64            `json:"rejected"`
	RejectReasons map[string]int64 `json:"rejectReasons,omitempty"`
}

type userIPEntry struct {
	conns    int64
	lastSeen time.Time
}

const cacheLinePad = 64 - 8

// UserCounter holds the counters of one user. up and down are written on every
// read and write of the user's connections, from different goroutines, so each
// sits on its own cache line.
type UserCounter struct {
	up   atomic.Int64
	_    [cacheLinePad]byte
	down atomic.Int64
	_    [cacheLinePad]byte

	conns atomic.Int64

	// limit is the user's limit state, nil when the user has no limit.
	limit atomic.Pointer[limitState]

	rejected    atomic.Int64
	rejectLogAt atomic.Int64 // unix nanoseconds of the last logged rejection
	suppressed  atomic.Int64 // rejections not logged since then

	mu          sync.Mutex
	reasons     map[string]int64
	ips         map[netip.Addr]*userIPEntry
	drainedUp   int64 // up and down at the last drain
	drainedDown int64
	observed    int64 // up+down when the activity was last observed
	lastActive  time.Time
	retired     bool
	deleted     bool
}

// AddUp adds n uploaded bytes.
func (c *UserCounter) AddUp(n int64) { c.up.Add(n) }

// AddDown adds n downloaded bytes.
func (c *UserCounter) AddDown(n int64) { c.down.Add(n) }

// addInitial counts the bytes a connection carried before it was tracked (a
// peeked request), against the quota too but without waiting for the speed
// limit.
func (c *UserCounter) addInitial(up, down int64) {
	if c == nil || up+down == 0 {
		return
	}
	c.up.Add(up)
	c.down.Add(down)
	if l := c.limit.Load(); l != nil {
		l.charge(up + down)
	}
}

// observe moves lastActive forward when bytes moved since the last look.
// c.mu must be held.
func (c *UserCounter) observe(now time.Time) {
	if total := c.up.Load() + c.down.Load(); total != c.observed {
		c.observed = total
		c.lastActive = now
	}
}

// acquire registers a new connection from ip; ok is false when the sweep has
// already deleted the counter. With lim set, the limits are checked first and
// a refused connection is not registered but reported in err. fresh is set
// when ip was not online for the user (see the auth events).
func (c *UserCounter) acquire(key UserKey, ip netip.Addr, now time.Time, lim *limitState, ipRelease time.Duration) (ok, fresh bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.deleted {
		return false, false, nil
	}
	if lim != nil {
		if reason, detail := lim.check(c, ip, now, ipRelease); reason != "" {
			return true, false, c.reject(key, ip, reason, detail, now)
		}
	}
	c.conns.Add(1)
	c.lastActive = now
	if ip.IsValid() {
		e := c.ips[ip]
		if e == nil {
			if c.ips == nil {
				c.ips = make(map[netip.Addr]*userIPEntry)
			}
			e = &userIPEntry{}
			c.ips[ip] = e
		}
		fresh = e.conns <= 0 && (e.lastSeen.IsZero() || now.Sub(e.lastSeen) > ipRelease)
		e.conns++
		e.lastSeen = now
	}
	return true, fresh, nil
}

const rejectLogInterval = time.Second

// reject counts a refused connection; c.mu must be held.
func (c *UserCounter) reject(key UserKey, ip netip.Addr, reason, detail string, now time.Time) *LimitError {
	c.rejected.Add(1)
	if c.reasons == nil {
		c.reasons = make(map[string]int64)
	}
	c.reasons[reason]++
	err := &LimitError{Key: key, Reason: reason, Detail: detail}
	if last := c.rejectLogAt.Load(); now.UnixNano()-last < int64(rejectLogInterval) {
		c.suppressed.Add(1)
		err.Quiet = true
	} else {
		c.rejectLogAt.Store(now.UnixNano())
		err.Suppressed = c.suppressed.Swap(0)
		if eventbus.Enabled(eventbus.TypeUserLimit) {
			d := eventbus.UserLimit{Inbound: key.Inbound, User: key.User, Reason: reason, Action: eventbus.LimitRejected, Detail: detail, Suppressed: err.Suppressed}
			if ip.IsValid() {
				d.Remote = ip.String()
			}
			eventbus.Publish(eventbus.TypeUserLimit, d)
		}
	}
	return err
}

func (c *UserCounter) release(ip netip.Addr, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conns.Add(-1)
	c.observe(now)
	c.lastActive = now
	if e := c.ips[ip]; e != nil && e.conns > 0 {
		e.conns--
		e.lastSeen = now
	}
}

// stat builds a snapshot; c.mu must be held.
func (c *UserCounter) stat(key UserKey, now time.Time, drain bool) UserStat {
	c.observe(now)
	up, down := c.up.Load(), c.down.Load()
	s := UserStat{
		Inbound:    key.Inbound,
		User:       key.User,
		Up:         up,
		Down:       down,
		Conns:      c.conns.Load(),
		LastActive: c.lastActive,
		IPs:        make([]UserIP, 0, len(c.ips)),
		Rejected:   c.rejected.Load(),
	}
	if len(c.reasons) > 0 {
		s.RejectReasons = make(map[string]int64, len(c.reasons))
		for k, v := range c.reasons {
			s.RejectReasons[k] = v
		}
	}
	if drain {
		s.Up, s.Down = up-c.drainedUp, down-c.drainedDown
		c.drainedUp, c.drainedDown = up, down
	}
	for ip, e := range c.ips {
		s.IPs = append(s.IPs, UserIP{IP: ip, Conns: e.conns, LastSeen: e.lastSeen})
	}
	sort.Slice(s.IPs, func(i, j int) bool { return s.IPs[i].IP.Less(s.IPs[j].IP) })
	return s
}

// UserManager keeps the counters of all users.
type UserManager struct {
	counters xsync.Map[UserKey, *UserCounter]

	// IdleTTL is how long a counter without connections and traffic is kept;
	// IPRelease is how long an address is listed after its last connection.
	IdleTTL   time.Duration
	IPRelease time.Duration

	now func() time.Time

	// the limits: lspecs are the configured ones (by user, or "*" for an
	// inbound default), lstates the state of every user with a limit.
	// limitsOn tells the hot paths whether there is any limit at all.
	limitsOn atomic.Bool
	lmu      sync.Mutex
	lspecs   map[UserKey]limitEntry
	lstates  map[UserKey]*limitState
	closer   func(key UserKey, still func() bool)
}

// NewUserManager returns an empty manager with the default timeouts.
func NewUserManager() *UserManager {
	return &UserManager{IdleTTL: defaultUserIdleTTL, IPRelease: defaultUserIPRelease, now: time.Now}
}

// Acquire returns the counter of key with a connection from ip registered on
// it, without checking the user's limits (see Admit). The caller must call
// Release with the same ip exactly once.
func (um *UserManager) Acquire(key UserKey, ip netip.Addr) *UserCounter {
	c, _ := um.acquire(key, ip, false)
	return c
}

// Release unregisters a connection acquired with Acquire.
func (um *UserManager) Release(c *UserCounter, ip netip.Addr) {
	c.release(ip, um.now())
}

func (um *UserManager) collect(filter func(UserKey) bool, drain bool) []UserStat {
	now := um.now()
	stats := make([]UserStat, 0)
	um.counters.Range(func(key UserKey, c *UserCounter) bool {
		if filter != nil && !filter(key) {
			return true
		}
		c.mu.Lock()
		if !c.deleted {
			stats = append(stats, c.stat(key, now, drain))
		}
		c.mu.Unlock()
		return true
	})
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Inbound != stats[j].Inbound {
			return stats[i].Inbound < stats[j].Inbound
		}
		return stats[i].User < stats[j].User
	})
	return stats
}

// Snapshot returns the cumulative counters of all users.
func (um *UserManager) Snapshot() []UserStat { return um.collect(nil, false) }

// SnapshotFunc returns the cumulative counters of the users that filter accepts.
func (um *UserManager) SnapshotFunc(filter func(UserKey) bool) []UserStat {
	return um.collect(filter, false)
}

// Drain returns the bytes of every user since the previous drain and starts a
// new period ("query with reset"): no byte is reported twice or lost. Snapshot
// stays cumulative.
func (um *UserManager) Drain() []UserStat { return um.collect(nil, true) }

// DrainFunc drains only the users that filter accepts.
func (um *UserManager) DrainFunc(filter func(UserKey) bool) []UserStat {
	return um.collect(filter, true)
}

// Get returns the cumulative counters of one user.
func (um *UserManager) Get(key UserKey) (UserStat, bool) {
	c, ok := um.counters.Load(key)
	if !ok {
		return UserStat{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.deleted {
		return UserStat{}, false
	}
	return c.stat(key, um.now(), false), true
}

// Len returns the number of counters.
func (um *UserManager) Len() int { return um.counters.Size() }

// Retire marks the users for which keep returns false as gone from the
// configuration (after a reload), so the sweep removes them as soon as they
// have no connections and their bytes were drained. A key that keep accepts
// again is no longer retired.
func (um *UserManager) Retire(keep func(UserKey) bool) {
	um.counters.Range(func(key UserKey, c *UserCounter) bool {
		retired := !keep(key)
		c.mu.Lock()
		c.retired = retired
		c.mu.Unlock()
		return true
	})
}

// SetRetired marks the counters of the given users of an inbound as retired
// (removed from the inbound at runtime: dropped once their connections are
// closed and their bytes drained) or no longer retired (added back).
func (um *UserManager) SetRetired(inbound string, users []string, retired bool) {
	for _, user := range users {
		if c, ok := um.counters.Load(UserKey{Inbound: inbound, User: user}); ok {
			c.mu.Lock()
			c.retired = retired
			c.mu.Unlock()
		}
	}
}

// Sweep removes counters that are retired or idle longer than IdleTTL, have no
// connections and have nothing left to drain (or are idle longer than twice
// IdleTTL), and forgets addresses closed longer than IPRelease ago.
func (um *UserManager) Sweep() {
	now := um.now()
	um.counters.Range(func(key UserKey, c *UserCounter) bool {
		c.mu.Lock()
		c.observe(now)
		for ip, e := range c.ips {
			if e.conns <= 0 && now.Sub(e.lastSeen) > um.IPRelease {
				delete(c.ips, ip)
			}
		}
		idle := now.Sub(c.lastActive)
		drained := c.up.Load() == c.drainedUp && c.down.Load() == c.drainedDown
		if c.conns.Load() == 0 && (c.retired || idle > um.IdleTTL) && (drained || idle > 2*um.IdleTTL) {
			c.deleted = true
		}
		deleted := c.deleted
		c.mu.Unlock()
		if deleted {
			um.counters.Compute(key, func(old *UserCounter, loaded bool) (*UserCounter, xsync.ComputeOp) {
				if loaded && old == c {
					return nil, xsync.DeleteOp
				}
				return old, xsync.CancelOp
			})
			if c.limit.Load() != nil {
				um.pruneLimitState(key)
			}
		}
		return true
	})
}

// userBinding is what a tracker keeps: the counter and the address it was
// acquired with.
type userBinding struct {
	manager *UserManager
	counter *UserCounter
	ip      netip.Addr
}

func bindUser(manager *Manager, metadata *C.Metadata, pushToManager bool) userBinding {
	if !pushToManager || metadata == nil || metadata.InUser == "" {
		return userBinding{}
	}
	um := manager.Users()
	if !userStatsEnabled.Load() && !um.limitsOn.Load() {
		return userBinding{}
	}
	ip := metadata.SrcIP.Unmap()
	return userBinding{
		manager: um,
		counter: um.Acquire(UserKey{Inbound: metadata.InName, User: metadata.InUser}, ip),
		ip:      ip,
	}
}

// Admission is a connection of a user admitted by its limits before the
// outbound is dialed. It is handed to NewTCPTrackerAdmitted or
// NewUDPTrackerAdmitted, which release it when the connection is closed; when
// no tracker is created (the dial failed), Release must be called instead.
type Admission struct {
	binding userBinding
}

// Release gives back an admission that no tracker took over.
func (a Admission) Release() { a.binding.release() }

// Admit checks the limits of the inbound user of metadata and registers the
// new connection on its counter. It fails with a *LimitError when the limits
// refuse it. Connections without a user are always admitted.
func (m *Manager) Admit(metadata *C.Metadata) (Admission, error) {
	if metadata == nil || metadata.InUser == "" {
		return Admission{}, nil
	}
	um := m.Users()
	if !userStatsEnabled.Load() && !um.limitsOn.Load() {
		return Admission{}, nil
	}
	ip := metadata.SrcIP.Unmap()
	c, err := um.Admit(UserKey{Inbound: metadata.InName, User: metadata.InUser}, ip)
	if err != nil {
		return Admission{}, err
	}
	return Admission{binding: userBinding{manager: um, counter: c, ip: ip}}, nil
}

func (b userBinding) release() {
	if b.counter != nil {
		b.manager.Release(b.counter, b.ip)
	}
}
