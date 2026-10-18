package statistic

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/eventbus"
	"github.com/metacubex/mihomo/log"
)

// Per-user limits.
//
// A limit applies to a user of an inbound (the same pair as the traffic
// counters); a limit with User "*" is the default of every user of that
// inbound without a limit of its own. The limits are enforced by the tunnel:
//
//   - expire-at, quota, max-conns and max-ips are checked when a connection or
//     UDP session of the user is admitted, after the rules matched and before
//     the outbound is dialed; a rejected connection is closed and counted in
//     the user's counter (rejected, rejectReasons);
//   - speed-up and speed-down are token buckets shared by all the user's
//     connections, applied in the tracker read and write paths;
//   - when the quota is used up or the user expires, the user's open
//     connections are closed.
//
// A user without limits pays nothing more than before: its counter has a nil
// limit pointer.

// AnyUser as UserLimit.User makes the limit the default of the inbound.
const AnyUser = "*"

// Sources of a limit.
const (
	LimitSourceConfig = "config"
	LimitSourceAPI    = "api"
)

// Reasons of a rejection.
const (
	RejectExpired  = "expired"
	RejectQuota    = "quota"
	RejectMaxConns = "max-conns"
	RejectMaxIPs   = "max-ips"
)

// UserLimit is the limits of a user of an inbound. A zero field is no limit.
type UserLimit struct {
	Inbound string `json:"inbound"`
	User    string `json:"user"`
	// SpeedUp and SpeedDown are in bytes per second.
	SpeedUp   int64 `json:"speedUp"`
	SpeedDown int64 `json:"speedDown"`
	// MaxConns is the number of open connections and UDP sessions.
	MaxConns int64 `json:"maxConns"`
	// MaxIPs is the number of online source addresses (see UserStat.IPs).
	MaxIPs int64 `json:"maxIPs"`
	// Quota is the traffic budget in bytes, upload plus download.
	Quota int64 `json:"quota"`
	// ExpireAt is a unix time in seconds.
	ExpireAt int64 `json:"expireAt"`
}

// Key returns the user the limit is for.
func (l UserLimit) Key() UserKey { return UserKey{Inbound: l.Inbound, User: l.User} }

// Validate checks the limit.
func (l UserLimit) Validate() error {
	switch {
	case l.Inbound == "":
		return errors.New("inbound is required")
	case l.User == "":
		return errors.New(`user is required ("*" for the default of the inbound)`)
	case l.SpeedUp < 0, l.SpeedDown < 0, l.MaxConns < 0, l.MaxIPs < 0, l.Quota < 0, l.ExpireAt < 0:
		return errors.New("limits must not be negative")
	}
	return nil
}

func (l UserLimit) speedEqual(o UserLimit) bool {
	return l.SpeedUp == o.SpeedUp && l.SpeedDown == o.SpeedDown
}

// UserLimitStatus is a limit with its state, as reported by the API.
type UserLimitStatus struct {
	UserLimit
	// Source is "config" or "api"; empty for a limit inherited from the
	// default of the inbound.
	Source string `json:"source,omitempty"`
	// Inherited is set for a user that has the default limit of the inbound.
	Inherited bool `json:"inherited,omitempty"`
	// Used is the bytes counted against the quota since the limit was set or
	// the quota was reset; Remaining is the rest of the quota (null when
	// there is no quota).
	Used          int64  `json:"used"`
	Remaining     *int64 `json:"remaining"`
	QuotaExceeded bool   `json:"quotaExceeded"`
	Expired       bool   `json:"expired"`
}

// LimitError is the error of a rejected connection.
type LimitError struct {
	Key    UserKey
	Reason string
	Detail string
	// Suppressed is the number of rejections of the user not logged since
	// the previous logged one; Quiet asks the caller not to log this one
	// (a user is logged at most once a second).
	Suppressed int64
	Quiet      bool
}

func (e *LimitError) Error() string {
	return fmt.Sprintf("user %s of %s rejected: %s", e.Key.User, e.Key.Inbound, e.Detail)
}

// tokenBucket is a lock-free rate limiter (GCRA): tat is the time at which the
// bucket would be full again. take never refuses; it returns how long the
// caller has to wait so that the bytes taken keep to the rate.
type tokenBucket struct {
	rate  int64 // bytes per second
	burst int64 // tolerance in nanoseconds
	tat   atomic.Int64
}

const limitBurst = 100 * time.Millisecond

var monoStart = time.Now()

func monoNow() int64 { return int64(time.Since(monoStart)) }

func newTokenBucket(rate int64) *tokenBucket {
	if rate <= 0 {
		return nil
	}
	return &tokenBucket{rate: rate, burst: int64(limitBurst)}
}

func (b *tokenBucket) take(n int64) time.Duration { return b.takeAt(n, monoNow) }

func (b *tokenBucket) takeAt(n int64, clock func() int64) time.Duration {
	if n <= 0 {
		return 0
	}
	cost := int64(float64(n) * float64(time.Second) / float64(b.rate))
	for {
		now := clock()
		old := b.tat.Load()
		tat := maxInt64(old, now-b.burst) + cost
		if b.tat.CompareAndSwap(old, tat) {
			if d := tat - now; d > 0 {
				return time.Duration(d)
			}
			return 0
		}
	}
}

// waitClosed sleeps for d, waking up early when closed is set.
func waitClosed(d time.Duration, closed *atomic.Bool) {
	const slice = 250 * time.Millisecond
	for d > 0 && (closed == nil || !closed.Load()) {
		s := d
		if s > slice {
			s = slice
		}
		time.Sleep(s)
		d -= s
	}
}

// limitState is the state of the limits of one user: the effective limit,
// the token buckets and the quota usage. It outlives the user's counter (the
// usage is kept when the user is idle) and is dropped when the user has no
// limit any more.
type limitState struct {
	key UserKey
	um  *UserManager

	spec    atomic.Pointer[UserLimit]
	up      atomic.Pointer[tokenBucket]
	down    atomic.Pointer[tokenBucket]
	quota   atomic.Int64
	used    atomic.Int64
	tripped atomic.Bool
	// dropped is set when the user has no limit any more
	dropped atomic.Bool

	// guarded by UserManager.lmu
	inherited bool
	timer     *time.Timer
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func (l *limitState) addUp(n int64, closed *atomic.Bool) {
	l.charge(n)
	if b := l.up.Load(); b != nil {
		waitClosed(b.take(n), closed)
	}
}

func (l *limitState) addDown(n int64, closed *atomic.Bool) {
	l.charge(n)
	if b := l.down.Load(); b != nil {
		waitClosed(b.take(n), closed)
	}
}

func (l *limitState) charge(n int64) {
	used := l.used.Add(n)
	if q := l.quota.Load(); q > 0 && used >= q && !l.tripped.Load() && l.tripped.CompareAndSwap(false, true) {
		log.Infoln("[Limits] user %s of %s used up the quota of %d bytes, closing its connections", l.key.User, l.key.Inbound, q)
		publishLimitClosed(l.key, RejectQuota, fmt.Sprintf("quota of %d bytes used up", q))
		go l.um.closeUser(l.key, l.overQuota)
	}
}

// ErrQuotaExceeded is returned by the reads and writes of a user's connections
// once the user's quota is used up, so that a fast transfer stops at once
// instead of running on until the connections are closed.
var ErrQuotaExceeded = errors.New("user quota exceeded")

// overQuota reports whether the user's quota is used up.
func (l *limitState) overQuota() bool { return l.tripped.Load() }

// hasQuota reports whether the user has a quota.
func (l *limitState) hasQuota() bool { return l.quota.Load() > 0 }

func (l *limitState) hasSpeed(up bool) bool {
	if up {
		return l.up.Load() != nil
	}
	return l.down.Load() != nil
}

// apply sets the effective limit; lmu must be held.
func (l *limitState) apply(spec UserLimit, inherited bool, now time.Time) {
	spec.Inbound, spec.User = l.key.Inbound, l.key.User
	old := l.spec.Load()
	l.inherited = inherited
	l.spec.Store(&spec)
	if old == nil || !old.speedEqual(spec) {
		l.up.Store(newTokenBucket(spec.SpeedUp))
		l.down.Store(newTokenBucket(spec.SpeedDown))
	}
	l.quota.Store(spec.Quota)
	exceeded := spec.Quota > 0 && l.used.Load() >= spec.Quota
	if l.tripped.Swap(exceeded) != exceeded && exceeded {
		log.Infoln("[Limits] user %s of %s is over the new quota of %d bytes, closing its connections", l.key.User, l.key.Inbound, spec.Quota)
		publishLimitClosed(l.key, RejectQuota, fmt.Sprintf("quota of %d bytes used up", spec.Quota))
		go l.um.closeUser(l.key, l.overQuota)
	}
	if old == nil || old.ExpireAt != spec.ExpireAt {
		l.stopTimer()
		if spec.ExpireAt > 0 {
			d := time.Unix(spec.ExpireAt, 0).Sub(now)
			expired := fmt.Sprintf("expired at %s", time.Unix(spec.ExpireAt, 0).UTC().Format(time.RFC3339))
			expireAt := spec.ExpireAt
			stillExpired := func() bool { return !l.dropped.Load() && l.spec.Load().ExpireAt == expireAt }
			if d <= 0 {
				publishLimitClosed(l.key, RejectExpired, expired)
				go l.um.closeUser(l.key, stillExpired)
			} else {
				key := l.key
				l.timer = time.AfterFunc(d, func() {
					// the timer runs on the monotonic clock and ExpireAt is wall-clock time: if the
					// wall clock was slewed meanwhile, wait for it, or the user is closed while
					// still admitted and reconnects until the second turns
					if early := time.Until(time.Unix(expireAt, 0)); early > 0 {
						time.Sleep(early)
					}
					if !stillExpired() { // changed while waiting
						return
					}
					log.Infoln("[Limits] user %s of %s expired, closing its connections", key.User, key.Inbound)
					publishLimitClosed(key, RejectExpired, expired)
					l.um.closeUser(key, stillExpired)
				})
			}
		}
	}
}

// publishLimitClosed reports a user whose connections are closed because it
// used up its quota or expired.
func publishLimitClosed(key UserKey, reason, detail string) {
	if eventbus.Enabled(eventbus.TypeUserLimit) {
		eventbus.Publish(eventbus.TypeUserLimit, eventbus.UserLimit{Inbound: key.Inbound, User: key.User, Reason: reason, Action: eventbus.LimitClosed, Detail: detail})
	}
}

func (l *limitState) stopTimer() {
	if l.timer != nil {
		l.timer.Stop()
		l.timer = nil
	}
}

// check returns why a new connection from ip is refused; c.mu must be held.
func (l *limitState) check(c *UserCounter, ip netip.Addr, now time.Time, ipRelease time.Duration) (reason, detail string) {
	spec := l.spec.Load()
	if spec.ExpireAt > 0 && now.Unix() >= spec.ExpireAt {
		return RejectExpired, fmt.Sprintf("expired at %s", time.Unix(spec.ExpireAt, 0).UTC().Format(time.RFC3339))
	}
	if q := l.quota.Load(); q > 0 && l.used.Load() >= q {
		return RejectQuota, fmt.Sprintf("quota of %d bytes used up", q)
	}
	if spec.MaxConns > 0 && c.conns.Load() >= spec.MaxConns {
		return RejectMaxConns, fmt.Sprintf("max-conns %d reached", spec.MaxConns)
	}
	if spec.MaxIPs > 0 && ip.IsValid() {
		if e := c.ips[ip]; e == nil || (e.conns <= 0 && now.Sub(e.lastSeen) > ipRelease) {
			var online int64
			for _, e := range c.ips {
				if e.conns > 0 || now.Sub(e.lastSeen) <= ipRelease {
					online++
				}
			}
			if online >= spec.MaxIPs {
				return RejectMaxIPs, fmt.Sprintf("max-ips %d reached, %s is a new address", spec.MaxIPs, ip)
			}
		}
	}
	return "", ""
}

func (l *limitState) status(now time.Time) UserLimitStatus {
	s := UserLimitStatus{
		UserLimit: *l.spec.Load(),
		Inherited: l.inherited,
		Used:      l.used.Load(),
	}
	if s.Quota > 0 {
		r := maxInt64(s.Quota-s.Used, 0)
		s.Remaining = &r
		s.QuotaExceeded = s.Used >= s.Quota
	}
	s.Expired = s.ExpireAt > 0 && now.Unix() >= s.ExpireAt
	return s
}

type limitEntry struct {
	spec   UserLimit
	source string
}

// lookupLocked returns the limit of key: its own, or the default of its
// inbound. lmu must be held.
func (um *UserManager) lookupLocked(key UserKey) (UserLimit, bool, bool) {
	if e, ok := um.lspecs[key]; ok {
		return e.spec, false, true
	}
	if key.User != AnyUser {
		if e, ok := um.lspecs[UserKey{Inbound: key.Inbound, User: AnyUser}]; ok {
			return e.spec, true, true
		}
	}
	return UserLimit{}, false, false
}

// stateLocked returns the limit state of a user, creating it when the user
// has a limit; nil when it has none. lmu must be held.
func (um *UserManager) stateLocked(key UserKey, now time.Time) *limitState {
	if l := um.lstates[key]; l != nil {
		return l
	}
	spec, inherited, ok := um.lookupLocked(key)
	if !ok || key.User == AnyUser {
		return nil
	}
	l := &limitState{key: key, um: um}
	l.apply(spec, inherited, now)
	if um.lstates == nil {
		um.lstates = make(map[UserKey]*limitState)
	}
	um.lstates[key] = l
	return l
}

// rebuildLocked brings the states and the counters in line with the specs
// after a change. lmu must be held.
func (um *UserManager) rebuildLocked() {
	now := um.now()
	for key, l := range um.lstates {
		spec, inherited, ok := um.lookupLocked(key)
		if !ok {
			l.stopTimer()
			// a pass closing the user's connections that is still to run
			// must not close those opened now that the user has no limit
			l.tripped.Store(false)
			l.dropped.Store(true)
			delete(um.lstates, key)
			continue
		}
		l.apply(spec, inherited, now)
	}
	for key := range um.lspecs {
		if key.User != AnyUser {
			um.stateLocked(key, now)
		}
	}
	um.limitsOn.Store(len(um.lspecs) > 0)
	um.counters.Range(func(key UserKey, c *UserCounter) bool {
		if l := um.lstates[key]; l != nil {
			c.limit.Store(l)
		} else if um.limitsOn.Load() {
			c.limit.Store(um.stateLocked(key, now))
		} else {
			c.limit.Store(nil)
		}
		return true
	})
}

// SetLimit sets the limit of a user (or with User "*" the default of the
// inbound) from the API. The quota usage of the user is kept. A configuration
// reload replaces the limits set this way.
func (um *UserManager) SetLimit(l UserLimit) error {
	return um.setLimit(l, LimitSourceAPI)
}

func (um *UserManager) setLimit(l UserLimit, source string) error {
	if err := l.Validate(); err != nil {
		return err
	}
	um.lmu.Lock()
	defer um.lmu.Unlock()
	if um.lspecs == nil {
		um.lspecs = make(map[UserKey]limitEntry)
	}
	um.lspecs[l.Key()] = limitEntry{spec: l, source: source}
	um.rebuildLocked()
	return nil
}

// DeleteLimit removes the limit of a user (or the default of an inbound); a
// user with a default falls back to it. It reports whether there was one.
func (um *UserManager) DeleteLimit(key UserKey) bool {
	um.lmu.Lock()
	defer um.lmu.Unlock()
	if _, ok := um.lspecs[key]; !ok {
		return false
	}
	delete(um.lspecs, key)
	um.rebuildLocked()
	return true
}

// SetConfigLimits replaces all the limits with those of the configuration.
// The limits set through the API are dropped; the state of a user that still
// has a limit (quota usage, rate buckets when the speed is unchanged, expiry
// timer when expire-at is unchanged) is kept.
func (um *UserManager) SetConfigLimits(limits []UserLimit) error {
	specs := make(map[UserKey]limitEntry, len(limits))
	for _, l := range limits {
		if err := l.Validate(); err != nil {
			return fmt.Errorf("user-limits %s/%s: %w", l.Inbound, l.User, err)
		}
		if _, dup := specs[l.Key()]; dup {
			return fmt.Errorf("user-limits: duplicate limit for user %q of %q", l.User, l.Inbound)
		}
		specs[l.Key()] = limitEntry{spec: l, source: LimitSourceConfig}
	}
	um.lmu.Lock()
	defer um.lmu.Unlock()
	um.lspecs = specs
	um.rebuildLocked()
	return nil
}

// ResetQuota sets the quota usage of the users that filter accepts (all when
// nil) back to zero, so users over their quota are admitted again. It returns
// the number of users reset.
func (um *UserManager) ResetQuota(filter func(UserKey) bool) int {
	um.lmu.Lock()
	defer um.lmu.Unlock()
	n := 0
	for key, l := range um.lstates {
		if filter != nil && !filter(key) {
			continue
		}
		l.used.Store(0)
		l.tripped.Store(false)
		n++
	}
	return n
}

// Limits returns the limits (the defaults "*" included) and the users with an
// inherited default limit, with their state.
func (um *UserManager) Limits() []UserLimitStatus { return um.LimitsFunc(nil) }

// LimitsFunc returns the limits of the keys that filter accepts.
func (um *UserManager) LimitsFunc(filter func(UserKey) bool) []UserLimitStatus {
	now := um.now()
	um.lmu.Lock()
	out := make([]UserLimitStatus, 0, len(um.lstates)+len(um.lspecs))
	for key, e := range um.lspecs {
		if key.User != AnyUser || (filter != nil && !filter(key)) {
			continue
		}
		out = append(out, UserLimitStatus{UserLimit: e.spec, Source: e.source})
	}
	for key, l := range um.lstates {
		if filter != nil && !filter(key) {
			continue
		}
		s := l.status(now)
		if e, ok := um.lspecs[key]; ok {
			s.Source = e.source
		}
		out = append(out, s)
	}
	um.lmu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Inbound != out[j].Inbound {
			return out[i].Inbound < out[j].Inbound
		}
		return out[i].User < out[j].User
	})
	return out
}

// GetLimit returns the limit of a user (its own or the inherited default) or
// of an inbound default ("*").
func (um *UserManager) GetLimit(key UserKey) (UserLimitStatus, bool) {
	now := um.now()
	um.lmu.Lock()
	defer um.lmu.Unlock()
	e, own := um.lspecs[key]
	if key.User == AnyUser {
		return UserLimitStatus{UserLimit: e.spec, Source: e.source}, own
	}
	l := um.stateLocked(key, now)
	if l == nil {
		return UserLimitStatus{}, false
	}
	s := l.status(now)
	if own {
		s.Source = e.source
	}
	return s, true
}

// pruneLimitState drops the state of a user removed by the sweep when it only
// holds an inherited default without a quota or an expiry: nothing in it is
// worth keeping, and it is created again on the next connection. States with
// a quota keep the usage, so they stay.
func (um *UserManager) pruneLimitState(key UserKey) {
	um.lmu.Lock()
	defer um.lmu.Unlock()
	if l := um.lstates[key]; l != nil && l.inherited && l.quota.Load() == 0 && l.spec.Load().ExpireAt == 0 {
		if _, alive := um.counters.Load(key); !alive {
			delete(um.lstates, key)
		}
	}
}

// closeUser closes the open connections of a user while still reports that
// the reason to close them holds.
//
// It runs asynchronously, after the quota was used up or the user expired:
// by then the quota may have been reset, the quota raised or the expiry moved
// (by the API or a reload), and the user's new connections admitted since.
// The closer asks still before closing each connection, so that those are
// left alone.
func (um *UserManager) closeUser(key UserKey, still func() bool) {
	if f := um.closer; f != nil {
		f(key, still)
	}
}

// SetCloser sets the function that closes the connections of a user when its
// quota is used up or it expires. The function must close a connection only
// while still returns true (it is checked again for every connection), as
// the user may be admitted again before the function runs. Manager.Users sets
// it to close the tracked connections of the user.
func (um *UserManager) SetCloser(f func(key UserKey, still func() bool)) { um.closer = f }

// Admit registers a new connection from ip like Acquire, after checking the
// limits of the user: it fails with a *LimitError when the user is expired,
// over its quota, at max-conns, or at max-ips with ip a new address. The
// rejection is counted on the user's counter.
func (um *UserManager) Admit(key UserKey, ip netip.Addr) (*UserCounter, error) {
	return um.acquire(key, ip, true)
}

func (um *UserManager) acquire(key UserKey, ip netip.Addr, check bool) (*UserCounter, error) {
	now := um.now()
	var lim *limitState
	locked := false
	if um.limitsOn.Load() {
		um.lmu.Lock()
		locked = true
		lim = um.stateLocked(key, now)
	}
	for {
		c, _ := um.counters.LoadOrCompute(key, func() (*UserCounter, bool) {
			return &UserCounter{lastActive: now}, false
		})
		if !locked && um.limitsOn.Load() {
			// limits were set while the counter was being created: the
			// rebuild may have missed it
			um.lmu.Lock()
			locked = true
			lim = um.stateLocked(key, now)
		}
		if locked {
			c.limit.Store(lim)
		}
		var checkLim *limitState
		if check {
			checkLim = lim
		}
		ok, fresh, err := c.acquire(key, ip, now, checkLim, um.IPRelease)
		if ok {
			if locked {
				um.lmu.Unlock()
			}
			if err != nil {
				return nil, err
			}
			if fresh {
				eventbus.PublishAuthSuccess(key.Inbound, key.User, ip)
			}
			return c, nil
		}
		// the sweep is deleting this counter right now; the next load
		// finds the map without it
	}
}
