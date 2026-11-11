package config

import "testing"

func TestNTPSystemClockWriteRequiresUnsafeOptIn(t *testing.T) {
	cfg := &RawConfig{NTP: RawNTP{Enable: true, WriteToSystem: true}}
	if _, err := parseNTP(cfg); err == nil {
		t.Fatal("unauthenticated system-clock write was accepted without unsafe opt-in")
	}
	cfg.NTP.AllowUnsafeWriteToSystem = true
	if _, err := parseNTP(cfg); err != nil {
		t.Fatalf("explicit compatibility opt-in rejected: %v", err)
	}
}
