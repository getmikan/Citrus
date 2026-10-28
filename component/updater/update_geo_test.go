package updater

import (
	"errors"
	"testing"
	"time"
)

func TestGeoUpdaterKeepsTickingAfterStartupFailure(t *testing.T) {
	for _, tt := range []struct {
		name       string
		lastUpdate func() (time.Time, error)
	}{
		{"overdue", func() (time.Time, error) { return time.Now().Add(-48 * time.Hour), nil }},
		{"no update time", func() (time.Time, error) { return time.Time{}, errors.New("no database files") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ticks := make(chan time.Time, 1)
			calls := 0
			update := func() error {
				calls++
				if calls == 1 {
					return errors.New("download failed")
				}
				return nil
			}
			ticks <- time.Now()
			close(ticks)
			runGeoUpdater(24*time.Hour, ticks, tt.lastUpdate, update)
			if calls != 2 {
				t.Fatalf("got %d updates, want the startup update and one tick", calls)
			}
		})
	}

	// A fresh database is not updated at start.
	ticks := make(chan time.Time)
	close(ticks)
	calls := 0
	runGeoUpdater(24*time.Hour, ticks, func() (time.Time, error) { return time.Now(), nil }, func() error { calls++; return nil })
	if calls != 0 {
		t.Fatalf("fresh database updated %d times at start", calls)
	}
}
