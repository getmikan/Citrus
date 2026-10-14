package ntp

import "time"

const (
	// maxNTPStep is how far an NTP answer may move the clock relative to
	// the previous accepted answer plus the monotonic time since then. Real
	// drift between syncs is milliseconds.
	maxNTPStep = 10 * time.Minute
	// ntpConfirmations is how many consecutive, mutually consistent answers
	// it takes to accept a larger step (after a suspend, say, or when the
	// previous answer was the wrong one).
	ntpConfirmations = 3
	// largeInitialOffset only changes how loudly the first sync is logged:
	// devices without a real-time clock legitimately start decades off.
	largeInitialOffset = 24 * time.Hour
)

// stepGuard keeps one spoofed or broken NTP answer from moving Citrus's
// clock (used for certificate validation) or the system clock arbitrarily
// far. NTP is unauthenticated, so this bounds a single bad answer; it
// cannot stop an attacker who controls every answer.
type stepGuard struct {
	synced  bool
	lastMon time.Time // local time.Now() of the last accepted answer (monotonic reading)
	lastNTP time.Time // NTP time of the last accepted answer

	candMon   time.Time
	candNTP   time.Time
	candCount int
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// check reports whether the NTP time ntpTime, received at local time now
// (which must carry a monotonic reading), may be applied. step is how far it
// is from the clock predicted by the last accepted answer.
func (g *stepGuard) check(now, ntpTime time.Time) (ok bool, step time.Duration) {
	if !g.synced {
		g.accept(now, ntpTime)
		return true, 0
	}
	step = ntpTime.Sub(g.lastNTP.Add(now.Sub(g.lastMon)))
	if absDuration(step) <= maxNTPStep {
		g.accept(now, ntpTime)
		return true, step
	}
	if g.candCount > 0 && absDuration(ntpTime.Sub(g.candNTP.Add(now.Sub(g.candMon)))) <= maxNTPStep {
		g.candCount++
	} else {
		g.candCount = 1
	}
	g.candMon, g.candNTP = now, ntpTime
	if g.candCount >= ntpConfirmations {
		g.accept(now, ntpTime)
		return true, step
	}
	return false, step
}

func (g *stepGuard) accept(now, ntpTime time.Time) {
	g.synced = true
	g.lastMon, g.lastNTP = now, ntpTime
	g.candCount = 0
}
