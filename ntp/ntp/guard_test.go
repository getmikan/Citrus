package ntp

import (
	"testing"
	"time"
)

func TestStepGuard(t *testing.T) {
	var g stepGuard
	start := time.Now()
	real := start.Add(time.Minute)

	at := func(d time.Duration) time.Time { return start.Add(d) }

	// A bounded first answer is accepted.
	if ok, _ := g.check(at(0), real); !ok {
		t.Fatal("first sync rejected")
	}
	var fresh stepGuard
	if ok, _ := fresh.check(at(0), start.Add(40*365*24*time.Hour)); ok {
		t.Fatal("unbounded first sync accepted")
	}
	// Normal drift is accepted.
	if ok, _ := g.check(at(30*time.Minute), real.Add(30*time.Minute+50*time.Millisecond)); !ok {
		t.Fatal("small drift rejected")
	}
	// One spoofed answer a year off is rejected...
	if ok, step := g.check(at(60*time.Minute), real.Add(60*time.Minute+365*24*time.Hour)); ok || step < 364*24*time.Hour {
		t.Fatalf("large step accepted: %v %v", ok, step)
	}
	// ...and does not affect the next honest answer.
	if ok, _ := g.check(at(61*time.Minute), real.Add(61*time.Minute)); !ok {
		t.Fatal("honest answer after a spoofed one rejected")
	}

	// Repeated answers from the same unauthenticated source are not quorum.
	jump := 5 * time.Hour
	for i := range 3 {
		d := 62*time.Minute + time.Duration(i)*time.Second
		ok, _ := g.check(at(d), real.Add(d+jump))
		if ok {
			t.Fatalf("repeated unauthenticated answer %d accepted", i)
		}
	}
	// Inconsistent large answers never add up to a confirmation.
	for i := 0; i < 5; i++ {
		d := 70*time.Minute + time.Duration(i)*time.Second
		if ok, _ := g.check(at(d), real.Add(d+jump+time.Duration(i+1)*24*time.Hour)); ok {
			t.Fatalf("inconsistent answer %d accepted", i)
		}
	}
}
