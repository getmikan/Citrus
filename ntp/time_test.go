package ntp

import (
	"testing"
	"time"
)

func TestNowIgnoresUnauthenticatedOffset(t *testing.T) {
	old := GetOffset()
	t.Cleanup(func() { SetOffset(old) })
	SetOffset(365 * 24 * time.Hour)
	if skew := Now().Sub(time.Now()); skew > time.Second || skew < -time.Second {
		t.Fatalf("security clock used the NTP offset: %s", skew)
	}
}
