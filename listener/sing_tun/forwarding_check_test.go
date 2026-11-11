package sing_tun

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/eventbus"
	"github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/control"
	"github.com/metacubex/sing/common/x/list"
)

type fakeNetworkMonitor struct {
	mu        sync.Mutex
	callbacks list.List[tun.NetworkUpdateCallback]
}

func (m *fakeNetworkMonitor) RegisterCallback(callback tun.NetworkUpdateCallback) *list.Element[tun.NetworkUpdateCallback] {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callbacks.PushBack(callback)
}

func (m *fakeNetworkMonitor) UnregisterCallback(element *list.Element[tun.NetworkUpdateCallback]) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks.Remove(element)
}

func (m *fakeNetworkMonitor) emit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for e := m.callbacks.Front(); e != nil; e = e.Next() {
		e.Value()
	}
}

func (m *fakeNetworkMonitor) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callbacks.Len()
}

type fakeDefaultMonitor struct {
	mu        sync.Mutex
	current   *control.Interface
	callbacks list.List[tun.DefaultInterfaceUpdateCallback]
}

func (m *fakeDefaultMonitor) DefaultInterface() *control.Interface {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

func (m *fakeDefaultMonitor) RegisterCallback(callback tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callbacks.PushBack(callback)
}

func (m *fakeDefaultMonitor) UnregisterCallback(element *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks.Remove(element)
}

// set changes the default interface without telling the callbacks.
func (m *fakeDefaultMonitor) set(iface *control.Interface) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.current = iface
}

func (m *fakeDefaultMonitor) emit() {
	m.mu.Lock()
	callbacks := make([]tun.DefaultInterfaceUpdateCallback, 0, m.callbacks.Len())
	for e := m.callbacks.Front(); e != nil; e = e.Next() {
		callbacks = append(callbacks, e.Value)
	}
	current := m.current
	m.mu.Unlock()
	for _, callback := range callbacks {
		callback(current, 0)
	}
}

func (m *fakeDefaultMonitor) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callbacks.Len()
}

// interface index n has LUID 0x100+n; the TUN is "tun0" with index 100.
type checkFixture struct {
	mu       sync.Mutex
	rows     map[ipInterfaceKey]ipInterfaceFlags
	errs     map[ipInterfaceKey]error
	reads    atomic.Int64
	notices  []forwardingNotice
	debugs   []string
	bound    atomic.Pointer[control.Interface]
	network  *fakeNetworkMonitor
	defaultM *fakeDefaultMonitor
	checker  *forwardingChecker
}

const fakeTunIndex = 100

func luidOf(index int) uint64 { return 0x100 + uint64(index) }

func newCheckFixture(bindDefault bool, debounce, poll time.Duration) *checkFixture {
	fx := &checkFixture{
		rows:     make(map[ipInterfaceKey]ipInterfaceFlags),
		errs:     make(map[ipInterfaceKey]error),
		network:  &fakeNetworkMonitor{},
		defaultM: &fakeDefaultMonitor{},
	}
	env := forwardingCheckEnv{
		readFlags: func(key ipInterfaceKey) (ipInterfaceFlags, error) {
			fx.reads.Add(1)
			fx.mu.Lock()
			defer fx.mu.Unlock()
			if err := fx.errs[key]; err != nil {
				return ipInterfaceFlags{}, err
			}
			flags, ok := fx.rows[key]
			if !ok {
				return ipInterfaceFlags{}, fmt.Errorf("%w: fake", errIPInterfaceGone)
			}
			return flags, nil
		},
		indexToLUID: func(index int) (uint64, error) {
			if index < 0 {
				return 0, errors.New("fake: no such index")
			}
			return luidOf(index), nil
		},
		nameToLUID: func(name string) (uint64, error) {
			if name == "tun0" {
				return luidOf(fakeTunIndex), nil
			}
			return 0, errors.New("fake: no such interface")
		},
		boundInterface: func() (int, string) {
			if bound := fx.bound.Load(); bound != nil {
				return bound.Index, bound.Name
			}
			return 0, ""
		},
		report: func(n forwardingNotice) {
			fx.mu.Lock()
			defer fx.mu.Unlock()
			fx.notices = append(fx.notices, n)
		},
		debugf: func(format string, v ...any) {
			fx.mu.Lock()
			defer fx.mu.Unlock()
			fx.debugs = append(fx.debugs, fmt.Sprintf(format, v...))
		},
		debounce: debounce,
		poll:     poll,
	}
	fx.checker = newForwardingChecker(env, "tun0", bindDefault, fx.network, fx.defaultM)
	return fx
}

func (fx *checkFixture) put(index int, family uint16, flags ipInterfaceFlags) {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	fx.rows[ipInterfaceKey{LUID: luidOf(index), Family: family}] = flags
}

func (fx *checkFixture) remove(index int, family uint16) {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	delete(fx.rows, ipInterfaceKey{LUID: luidOf(index), Family: family})
}

func (fx *checkFixture) fail(index int, family uint16, err error) {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	if err == nil {
		delete(fx.errs, ipInterfaceKey{LUID: luidOf(index), Family: family})
	} else {
		fx.errs[ipInterfaceKey{LUID: luidOf(index), Family: family}] = err
	}
}

// take returns the notices since the previous call.
func (fx *checkFixture) take() []forwardingNotice {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	notices := fx.notices
	fx.notices = nil
	return notices
}

func (fx *checkFixture) debugCount() int {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return len(fx.debugs)
}

var (
	fwdOn  = ipInterfaceFlags{Forwarding: true}
	bothOn = ipInterfaceFlags{Forwarding: true, WeakHostSend: true}
)

func ethernet(index int) *control.Interface {
	return &control.Interface{Index: index, Name: fmt.Sprintf("Ethernet %d", index)}
}

func wantNotices(t *testing.T, got []forwardingNotice, want ...forwardingNotice) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("notices %+v, want %+v", got, want)
	}
	// order across interfaces and families is not fixed
	used := make([]bool, len(got))
	for _, w := range want {
		found := false
		for i, g := range got {
			if !used[i] && g == w {
				used[i], found = true, true
				break
			}
		}
		if !found {
			t.Fatalf("notices %+v, want %+v", got, want)
		}
	}
}

func TestForwardingCheckAppearRepeatClear(t *testing.T) {
	fx := newCheckFixture(true, time.Hour, time.Hour)
	fx.defaultM.set(ethernet(1))
	fx.put(1, afInet, ipInterfaceFlags{})
	fx.put(1, afInet6, ipInterfaceFlags{})
	c := fx.checker

	c.check()
	wantNotices(t, fx.take())

	fx.put(1, afInet, fwdOn)
	c.check()
	wantNotices(t, fx.take(), forwardingNotice{Interface: "Ethernet 1", Family: afInet, Flags: fwdOn, On: true})

	for i := 0; i < 5; i++ {
		c.check()
	}
	wantNotices(t, fx.take())

	// another flag turning on is a new state
	fx.put(1, afInet, bothOn)
	c.check()
	wantNotices(t, fx.take(), forwardingNotice{Interface: "Ethernet 1", Family: afInet, Flags: bothOn, On: true})
	c.check()
	wantNotices(t, fx.take())

	// IPv6 is reported on its own
	fx.put(1, afInet6, ipInterfaceFlags{WeakHostSend: true})
	c.check()
	wantNotices(t, fx.take(), forwardingNotice{Interface: "Ethernet 1", Family: afInet6, Flags: ipInterfaceFlags{WeakHostSend: true}, On: true})

	fx.put(1, afInet, ipInterfaceFlags{})
	c.check()
	wantNotices(t, fx.take(), forwardingNotice{Interface: "Ethernet 1", Family: afInet, Reason: forwardingClearedOff})
	c.check()
	wantNotices(t, fx.take())

	// it may come back
	fx.put(1, afInet, fwdOn)
	c.check()
	wantNotices(t, fx.take(), forwardingNotice{Interface: "Ethernet 1", Family: afInet, Flags: fwdOn, On: true})
}

func TestForwardingCheckTargetSwitch(t *testing.T) {
	fx := newCheckFixture(true, time.Hour, time.Hour)
	fx.defaultM.set(ethernet(1))
	fx.put(1, afInet, fwdOn)
	fx.put(2, afInet, fwdOn)
	c := fx.checker

	c.check()
	wantNotices(t, fx.take(), forwardingNotice{Interface: "Ethernet 1", Family: afInet, Flags: fwdOn, On: true})

	fx.defaultM.set(ethernet(2))
	c.check()
	wantNotices(t, fx.take(),
		forwardingNotice{Interface: "Ethernet 1", Family: afInet, Flags: fwdOn, Reason: forwardingClearedNotEgress},
		forwardingNotice{Interface: "Ethernet 2", Family: afInet, Flags: fwdOn, On: true})

	// no default interface: nothing is a target
	fx.defaultM.set(nil)
	c.check()
	wantNotices(t, fx.take(), forwardingNotice{Interface: "Ethernet 2", Family: afInet, Flags: fwdOn, Reason: forwardingClearedNotEgress})
	c.check()
	wantNotices(t, fx.take())
}

func TestForwardingCheckTargets(t *testing.T) {
	// without auto-detect-interface only interface-name counts
	fx := newCheckFixture(false, time.Hour, time.Hour)
	fx.defaultM.set(ethernet(1))
	fx.put(1, afInet, fwdOn)
	fx.put(3, afInet, fwdOn)
	fx.put(fakeTunIndex, afInet, fwdOn)
	c := fx.checker

	c.check()
	wantNotices(t, fx.take())

	fx.bound.Store(ethernet(3))
	c.check()
	wantNotices(t, fx.take(), forwardingNotice{Interface: "Ethernet 3", Family: afInet, Flags: fwdOn, On: true})

	// interface-name naming the default interface is checked once
	fx2 := newCheckFixture(true, time.Hour, time.Hour)
	fx2.defaultM.set(ethernet(1))
	fx2.bound.Store(ethernet(1))
	fx2.put(1, afInet, fwdOn)
	fx2.checker.check()
	wantNotices(t, fx2.take(), forwardingNotice{Interface: "Ethernet 1", Family: afInet, Flags: fwdOn, On: true})
	if reads := fx2.reads.Load(); reads != 2 {
		t.Fatalf("%d reads, want 2 (one interface, two families)", reads)
	}

	// the TUN is never a target, by name or by LUID
	fx3 := newCheckFixture(true, time.Hour, time.Hour)
	fx3.put(fakeTunIndex, afInet, bothOn)
	fx3.defaultM.set(&control.Interface{Index: fakeTunIndex, Name: "tun0"})
	fx3.checker.check()
	fx3.defaultM.set(&control.Interface{Index: fakeTunIndex, Name: "renamed"})
	fx3.checker.check()
	fx3.bound.Store(&control.Interface{Index: fakeTunIndex, Name: "tun0"})
	fx3.checker.check()
	wantNotices(t, fx3.take())
	if reads := fx3.reads.Load(); reads != 0 {
		t.Fatalf("the TUN was read %d times", reads)
	}

	// an index without a LUID is skipped
	fx4 := newCheckFixture(true, time.Hour, time.Hour)
	fx4.defaultM.set(&control.Interface{Index: -1, Name: "broken"})
	fx4.checker.check()
	fx4.checker.check()
	wantNotices(t, fx4.take())
}

func TestForwardingCheckReadErrors(t *testing.T) {
	fx := newCheckFixture(true, time.Hour, time.Hour)
	fx.defaultM.set(ethernet(1))
	c := fx.checker

	// no row at all (IPv6 off on the adapter, adapter gone): silent
	for i := 0; i < 3; i++ {
		c.check()
	}
	wantNotices(t, fx.take())
	if n := fx.debugCount(); n != 0 {
		t.Fatalf("%d debug lines for missing rows", n)
	}

	// access denied: one debug line per key, however often it is read
	denied := fmt.Errorf("%w: fake", errIPInterfaceDenied)
	fx.fail(1, afInet, denied)
	fx.fail(1, afInet6, denied)
	for i := 0; i < 5; i++ {
		c.check()
	}
	wantNotices(t, fx.take())
	if n := fx.debugCount(); n != 2 {
		t.Fatalf("%d debug lines, want 2", n)
	}

	// a failed read keeps the reported state
	fx.fail(1, afInet, nil)
	fx.fail(1, afInet6, nil)
	fx.put(1, afInet, fwdOn)
	c.check()
	wantNotices(t, fx.take(), forwardingNotice{Interface: "Ethernet 1", Family: afInet, Flags: fwdOn, On: true})
	fx.fail(1, afInet, errors.New("fake: other error"))
	for i := 0; i < 5; i++ {
		c.check()
	}
	wantNotices(t, fx.take())
	if n := fx.debugCount(); n != 3 {
		t.Fatalf("%d debug lines, want 3", n)
	}
	fx.fail(1, afInet, nil)
	c.check()
	wantNotices(t, fx.take())

	// the row going away clears it
	fx.remove(1, afInet)
	c.check()
	wantNotices(t, fx.take(), forwardingNotice{Interface: "Ethernet 1", Family: afInet, Flags: fwdOn, Reason: forwardingClearedGone})
	c.check()
	wantNotices(t, fx.take())
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestForwardingCheckWorker(t *testing.T) {
	fx := newCheckFixture(true, 20*time.Millisecond, time.Hour)
	fx.defaultM.set(ethernet(1))
	fx.put(1, afInet, fwdOn)
	c := fx.checker
	c.start()
	if fx.network.count() != 1 || fx.defaultM.count() != 1 {
		t.Fatal("callbacks not registered")
	}

	var got []forwardingNotice
	waitFor(t, "the first check", func() bool { got = append(got, fx.take()...); return len(got) > 0 })
	wantNotices(t, got, forwardingNotice{Interface: "Ethernet 1", Family: afInet, Flags: fwdOn, On: true})

	// a burst of events is one check after the debounce
	before := fx.reads.Load()
	fx.put(1, afInet6, fwdOn)
	for i := 0; i < 50; i++ {
		fx.network.emit()
		fx.defaultM.emit()
	}
	got = nil
	waitFor(t, "the debounced check", func() bool { got = append(got, fx.take()...); return len(got) > 0 })
	wantNotices(t, got, forwardingNotice{Interface: "Ethernet 1", Family: afInet6, Flags: fwdOn, On: true})
	time.Sleep(60 * time.Millisecond)
	if reads := fx.reads.Load() - before; reads != 2 {
		t.Fatalf("%d reads for a burst, want 2 (one check)", reads)
	}

	// a wake after a reload (interface-name) is a check too
	fx.bound.Store(ethernet(2))
	fx.put(2, afInet, bothOn)
	c.wake()
	got = nil
	waitFor(t, "the check after wake", func() bool { got = append(got, fx.take()...); return len(got) > 0 })
	wantNotices(t, got, forwardingNotice{Interface: "Ethernet 2", Family: afInet, Flags: bothOn, On: true})

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if fx.network.count() != 0 || fx.defaultM.count() != 0 {
		t.Fatal("callbacks not unregistered")
	}
	wantNotices(t, fx.take(),
		forwardingNotice{Interface: "Ethernet 1", Family: afInet, Flags: fwdOn, Reason: forwardingClearedStopped},
		forwardingNotice{Interface: "Ethernet 1", Family: afInet6, Flags: fwdOn, Reason: forwardingClearedStopped},
		forwardingNotice{Interface: "Ethernet 2", Family: afInet, Flags: bothOn, Reason: forwardingClearedStopped})

	// stopped: no more reads, events do not block, Close again is a no-op
	reads := fx.reads.Load()
	c.wake()
	c.wake()
	time.Sleep(60 * time.Millisecond)
	if fx.reads.Load() != reads {
		t.Fatal("read after Close")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	wantNotices(t, fx.take())
}

func TestForwardingCheckPoll(t *testing.T) {
	fx := newCheckFixture(true, time.Hour, 20*time.Millisecond)
	fx.defaultM.set(ethernet(1))
	fx.put(1, afInet, ipInterfaceFlags{})
	c := fx.checker
	c.start()
	defer c.Close()
	waitFor(t, "a few polls", func() bool { return fx.reads.Load() >= 6 })
	wantNotices(t, fx.take())
	// a change nobody signals is seen by the poll
	fx.put(1, afInet, fwdOn)
	var got []forwardingNotice
	waitFor(t, "the poll to see the flag", func() bool { got = append(got, fx.take()...); return len(got) > 0 })
	wantNotices(t, got, forwardingNotice{Interface: "Ethernet 1", Family: afInet, Flags: fwdOn, On: true})
}

func TestReportForwarding(t *testing.T) {
	mask, err := eventbus.ParseTypes(eventbus.TypeTunForwarding)
	if err != nil {
		t.Fatal(err)
	}
	events := eventbus.Subscribe(mask, 8)
	defer events.Close()

	logs := log.Subscribe()
	lines := make(chan log.Event, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range logs {
			if strings.Contains(e.Payload, "[TUN]") && strings.Contains(e.Payload, "Wi-Fi 2") {
				lines <- e
			}
		}
	}()
	defer func() {
		log.UnSubscribe(logs)
		<-done
	}()

	nextLine := func() log.Event {
		t.Helper()
		select {
		case e := <-lines:
			return e
		case <-time.After(3 * time.Second):
			t.Fatal("no log line")
			return log.Event{}
		}
	}
	nextEvent := func() eventbus.TunForwarding {
		t.Helper()
		select {
		case e := <-events.C():
			if e.Type != eventbus.TypeTunForwarding {
				t.Fatalf("event type %q", e.Type)
			}
			return e.Data.(eventbus.TunForwarding)
		case <-time.After(3 * time.Second):
			t.Fatal("no event")
			return eventbus.TunForwarding{}
		}
	}

	reportForwarding(forwardingNotice{Interface: "Wi-Fi 2", Family: afInet6, Flags: bothOn, On: true})
	line := nextLine()
	if line.LogLevel != log.WARNING {
		t.Fatalf("level %v, want warning", line.LogLevel)
	}
	for _, want := range []string{
		"[TUN] Forwarding and WeakHostSend are on for IPv6 on Wi-Fi 2",
		"loop back into the TUN",
		"Internet Connection Sharing and Mobile Hotspot",
		`Set-NetIPInterface -InterfaceAlias "Wi-Fi 2" -Forwarding Disabled -WeakHostSend Disabled`,
	} {
		if !strings.Contains(line.Payload, want) {
			t.Errorf("warning %q lacks %q", line.Payload, want)
		}
	}
	if d := nextEvent(); d != (eventbus.TunForwarding{Interface: "Wi-Fi 2", Family: "ipv6", Forwarding: true, WeakHostSend: true, State: eventbus.TunForwardingOn}) {
		t.Fatalf("event %+v", d)
	}

	reportForwarding(forwardingNotice{Interface: "Wi-Fi 2", Family: afInet, Reason: forwardingClearedOff})
	line = nextLine()
	if line.LogLevel != log.INFO || !strings.Contains(line.Payload, "Forwarding/WeakHostSend for IPv4 on Wi-Fi 2 no longer affects the TUN (turned off)") {
		t.Fatalf("info %v %q", line.LogLevel, line.Payload)
	}
	if d := nextEvent(); d != (eventbus.TunForwarding{Interface: "Wi-Fi 2", Family: "ipv4", State: eventbus.TunForwardingCleared, Reason: "off"}) {
		t.Fatalf("event %+v", d)
	}

	reportForwarding(forwardingNotice{Interface: "Wi-Fi 2", Family: afInet, Flags: fwdOn, Reason: forwardingClearedNotEgress})
	nextLine()
	if d := nextEvent(); d != (eventbus.TunForwarding{Interface: "Wi-Fi 2", Family: "ipv4", Forwarding: true, State: eventbus.TunForwardingCleared, Reason: "not-egress"}) {
		t.Fatalf("event %+v", d)
	}

	reportForwarding(forwardingNotice{Interface: "Wi-Fi 2", Family: afInet, Flags: ipInterfaceFlags{WeakHostSend: true}, On: true})
	if line = nextLine(); !strings.Contains(line.Payload, "[TUN] WeakHostSend is on for IPv4 on Wi-Fi 2:") {
		t.Fatalf("warning %q", line.Payload)
	}
	if d := nextEvent(); d != (eventbus.TunForwarding{Interface: "Wi-Fi 2", Family: "ipv4", WeakHostSend: true, State: eventbus.TunForwardingOn}) {
		t.Fatalf("event %+v", d)
	}
}
