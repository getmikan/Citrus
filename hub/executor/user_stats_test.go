package executor

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

func TestUpdateGeneralUserStats(t *testing.T) {
	old := GetGeneral()
	t.Cleanup(func() { updateGeneral(old, false) })
	general := *old
	general.UserStats = false
	updateGeneral(&general, false)
	if statistic.UserStatsEnabled() || GetGeneral().UserStats {
		t.Fatal("user-stats: false was not applied")
	}
	general.UserStats = true
	updateGeneral(&general, false)
	if !statistic.UserStatsEnabled() {
		t.Fatal("user-stats: true was not applied")
	}
}

func TestUserStatsDefault(t *testing.T) {
	cfg, err := config.Parse([]byte("mixed-port: 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.General.UserStats {
		t.Fatal("user-stats must be on by default")
	}
	cfg, err = config.Parse([]byte("user-stats: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.General.UserStats {
		t.Fatal("user-stats: false was not parsed")
	}
}

func TestRetireUsers(t *testing.T) {
	vless, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:    inbound.BaseOption{NameStr: "retire-vless", Listen: "127.0.0.1", Port: "0"},
		Users:         []inbound.VlessUser{{Username: "alice", UUID: "00000000-0000-0000-0000-000000000001"}},
		AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	um := statistic.NewUserManager()
	ip := netip.MustParseAddr("192.0.2.1")
	keys := map[statistic.UserKey]bool{ // key → kept
		{Inbound: "retire-vless", User: "alice"}: true,
		{Inbound: "retire-vless", User: "bob"}:   false, // removed from the listener
		{Inbound: "retire-gone", User: "carol"}:  false, // listener removed
		{Inbound: "DEFAULT-MIXED", User: "dave"}: true,  // built-in inbound
	}
	for key := range keys {
		um.Release(um.Acquire(key, ip), ip)
	}
	retireUsersIn(um, map[string]C.InboundListener{"retire-vless": vless})
	um.Sweep() // nothing to drain, no connections: retired counters go at once
	for key, kept := range keys {
		if _, ok := um.Get(key); ok != kept {
			t.Errorf("%v: kept %v, want %v", key, ok, kept)
		}
	}
}
