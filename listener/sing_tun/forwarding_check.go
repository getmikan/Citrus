package sing_tun

// Windows routes the packets of a socket bound with IP_UNICAST_IF by an
// unconstrained route lookup when the egress interface has Forwarding or
// WeakHostSend on, so the TUN's default route wins and the core's own
// connections loop back into the TUN. Internet Connection Sharing and Mobile
// Hotspot turn Forwarding on for the shared uplink and may leave it on.
//
// The core does not change these flags: turning them off breaks the sharing,
// so that is left to the user or the app that runs the core. forwardingChecker
// only reads them on the interfaces the core binds its sockets to and reports
// when they turn on or off, in the log and as a tun.forwarding event of
// GET /events. The system calls live in forwarding_check_windows.go.

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/eventbus"
	"github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/control"
	"github.com/metacubex/sing/common/x/list"
)

const (
	afInet  uint16 = 2  // AF_INET
	afInet6 uint16 = 23 // AF_INET6 on Windows
)

var (
	errIPInterfaceGone   = errors.New("ip interface not found")
	errIPInterfaceDenied = errors.New("access denied")
)

type ipInterfaceKey struct {
	LUID   uint64
	Family uint16
}

type ipInterfaceFlags struct {
	Forwarding   bool
	WeakHostSend bool
}

func (f ipInterfaceFlags) any() bool {
	return f.Forwarding || f.WeakHostSend
}

func (f ipInterfaceFlags) String() string {
	var names []string
	if f.Forwarding {
		names = append(names, "Forwarding")
	}
	if f.WeakHostSend {
		names = append(names, "WeakHostSend")
	}
	return strings.Join(names, " and ")
}

func familyName(family uint16) string {
	if family == afInet6 {
		return "IPv6"
	}
	return "IPv4"
}

// The parts of the sing-tun monitors the checker uses.
type networkUpdateSource interface {
	RegisterCallback(callback tun.NetworkUpdateCallback) *list.Element[tun.NetworkUpdateCallback]
	UnregisterCallback(element *list.Element[tun.NetworkUpdateCallback])
}

type defaultInterfaceSource interface {
	DefaultInterface() *control.Interface
	RegisterCallback(callback tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback]
	UnregisterCallback(element *list.Element[tun.DefaultInterfaceUpdateCallback])
}

// forwardingCheckEnv is what the checker needs from the system.
type forwardingCheckEnv struct {
	// readFlags reads the two flags of one MIB_IPINTERFACE_ROW. Errors wrap
	// errIPInterfaceGone when the interface or its family row does not exist.
	readFlags      func(key ipInterfaceKey) (ipInterfaceFlags, error)
	indexToLUID    func(index int) (uint64, error)
	nameToLUID     func(name string) (uint64, error)
	boundInterface func() (index int, name string) // interface-name; index 0 when unset or not found
	report         func(forwardingNotice)
	debugf         func(format string, v ...any)
	debounce       time.Duration
	poll           time.Duration
}

// Reasons of a cleared notice.
const (
	forwardingClearedOff       = "off"        // the flags were turned off
	forwardingClearedNotEgress = "not-egress" // the core no longer binds to the interface
	forwardingClearedGone      = "gone"       // the interface or its family row is gone
	forwardingClearedStopped   = "stopped"    // the TUN stopped
)

// forwardingNotice is a change of the flags of one interface and family as
// the core sees it: On when a flag turned on (or the set of flags that are on
// changed), otherwise cleared for Reason.
type forwardingNotice struct {
	Interface string
	Family    uint16
	Flags     ipInterfaceFlags // what is on now, or was on last for not-egress, gone and stopped
	On        bool
	Reason    string
}

type forwardingTarget struct {
	LUID uint64
	Name string
}

type reportedForwarding struct {
	name  string
	flags ipInterfaceFlags
}

// forwardingChecker watches the flags of the egress interfaces of one TUN
// listener with auto-route. The monitors' callbacks only wake its worker; the
// worker reads the flags after a short debounce and on a slow poll.
type forwardingChecker struct {
	env         forwardingCheckEnv
	tunName     string
	bindDefault bool // auto-detect-interface: the core binds its sockets to the default interface
	network     networkUpdateSource
	defaultIf   defaultInterfaceSource

	// owned by the worker, and by Close once the worker is gone
	tunLUID  uint64
	reported map[ipInterfaceKey]reportedForwarding
	readErr  map[ipInterfaceKey]string // last read error logged per key

	networkElement *list.Element[tun.NetworkUpdateCallback]
	defaultElement *list.Element[tun.DefaultInterfaceUpdateCallback]
	wakeCh         chan struct{}
	done           chan struct{}
	wg             sync.WaitGroup
	closeOnce      sync.Once
}

func newForwardingChecker(env forwardingCheckEnv, tunName string, bindDefault bool, network networkUpdateSource, defaultIf defaultInterfaceSource) *forwardingChecker {
	if env.report == nil {
		env.report = reportForwarding
	}
	if env.debugf == nil {
		env.debugf = log.Debugln
	}
	return &forwardingChecker{
		env:         env,
		tunName:     tunName,
		bindDefault: bindDefault,
		network:     network,
		defaultIf:   defaultIf,
		reported:    make(map[ipInterfaceKey]reportedForwarding),
		readErr:     make(map[ipInterfaceKey]string),
		wakeCh:      make(chan struct{}, 1),
		done:        make(chan struct{}),
	}
}

// start checks at once in the worker, then on every monitor event and poll.
func (c *forwardingChecker) start() {
	c.networkElement = c.network.RegisterCallback(c.wake)
	c.defaultElement = c.defaultIf.RegisterCallback(func(*control.Interface, int) { c.wake() })
	c.wg.Add(1)
	go c.loop()
}

// wake runs in the monitors' callbacks and in Listener.OnReload (interface-name
// may have changed): never block there, Unregister waits for the callbacks.
func (c *forwardingChecker) wake() {
	select {
	case c.wakeCh <- struct{}{}:
	default:
	}
}

func (c *forwardingChecker) loop() {
	defer c.wg.Done()
	c.check()
	poll := time.NewTicker(c.env.poll)
	defer poll.Stop()
	debounce := time.NewTimer(c.env.debounce)
	debounce.Stop()
	defer debounce.Stop()
	pending := false
	for {
		select {
		case <-c.done:
			return
		case <-c.wakeCh:
			// the first event of a burst arms the timer; later ones fold into it
			if !pending {
				pending = true
				debounce.Reset(c.env.debounce)
			}
		case <-debounce.C:
			pending = false
			c.check()
		case <-poll.C:
			if !pending {
				c.check()
			}
		}
	}
}

// targets are the interfaces the core's sockets are bound to: the default
// interface with auto-detect-interface and the interface of interface-name,
// never the TUN. Without either binding, Windows routes the core's sockets
// normally and the flags do no harm.
func (c *forwardingChecker) targets() []forwardingTarget {
	if c.tunLUID == 0 { // the TUN keeps its LUID for the session
		c.tunLUID, _ = c.env.nameToLUID(c.tunName)
	}
	var targets []forwardingTarget
	add := func(index int, name string) {
		if index == 0 || name == c.tunName {
			return
		}
		luid, err := c.env.indexToLUID(index)
		if err != nil {
			c.env.debugf("[TUN] interface %s: %v", name, err)
			return
		}
		if c.tunLUID != 0 && luid == c.tunLUID {
			return
		}
		for _, target := range targets {
			if target.LUID == luid {
				return
			}
		}
		targets = append(targets, forwardingTarget{LUID: luid, Name: name})
	}
	if c.bindDefault {
		if defaultInterface := c.defaultIf.DefaultInterface(); defaultInterface != nil {
			add(defaultInterface.Index, defaultInterface.Name)
		}
	}
	add(c.env.boundInterface())
	return targets
}

// check reads the flags of the targets and reports what changed since the
// previous check.
func (c *forwardingChecker) check() {
	targets := c.targets()
	wanted := make(map[uint64]bool, len(targets))
	for _, target := range targets {
		wanted[target.LUID] = true
		for _, family := range []uint16{afInet, afInet6} {
			c.checkKey(ipInterfaceKey{LUID: target.LUID, Family: family}, target.Name)
		}
	}
	for key, r := range c.reported {
		if !wanted[key.LUID] {
			c.clear(key, r, forwardingClearedNotEgress)
		}
	}
	for key := range c.readErr {
		if !wanted[key.LUID] {
			delete(c.readErr, key)
		}
	}
}

func (c *forwardingChecker) checkKey(key ipInterfaceKey, name string) {
	flags, err := c.env.readFlags(key)
	if err != nil {
		if errors.Is(err, errIPInterfaceGone) {
			delete(c.readErr, key)
			if r, ok := c.reported[key]; ok {
				c.clear(key, r, forwardingClearedGone)
			}
			return
		}
		// keep what was reported: a failed read says nothing about the flags.
		// Logged once per distinct error, at debug level.
		if msg := err.Error(); c.readErr[key] != msg {
			c.readErr[key] = msg
			c.env.debugf("[TUN] read Forwarding/WeakHostSend for %s on %s: %v", familyName(key.Family), name, err)
		}
		return
	}
	delete(c.readErr, key)
	r, reported := c.reported[key]
	if !flags.any() {
		if reported {
			delete(c.reported, key)
			c.env.report(forwardingNotice{Interface: name, Family: key.Family, Reason: forwardingClearedOff})
		}
		return
	}
	if reported && r.flags == flags && r.name == name {
		return
	}
	c.reported[key] = reportedForwarding{name: name, flags: flags}
	c.env.report(forwardingNotice{Interface: name, Family: key.Family, Flags: flags, On: true})
}

func (c *forwardingChecker) clear(key ipInterfaceKey, r reportedForwarding, reason string) {
	delete(c.reported, key)
	c.env.report(forwardingNotice{Interface: r.name, Family: key.Family, Flags: r.flags, Reason: reason})
}

// Close stops the worker and reports what was on as cleared. Listener.Close
// calls it before it closes the monitors.
func (c *forwardingChecker) Close() error {
	c.closeOnce.Do(func() {
		c.network.UnregisterCallback(c.networkElement)
		c.defaultIf.UnregisterCallback(c.defaultElement)
		close(c.done)
		c.wg.Wait()
		for key, r := range c.reported {
			c.clear(key, r, forwardingClearedStopped)
		}
	})
	return nil
}

// reportForwarding logs a notice and publishes it as a tun.forwarding event.
func reportForwarding(n forwardingNotice) {
	family := familyName(n.Family)
	if n.On {
		verb := "is"
		if n.Flags.Forwarding && n.Flags.WeakHostSend {
			verb = "are"
		}
		log.Warnln("[TUN] %s %s on for %s on %s: Windows then ignores the interface the core binds its connections to, "+
			"so they loop back into the TUN (loopback rejects, DNS fails, no traffic). Internet Connection Sharing and Mobile Hotspot turn Forwarding on "+
			"and may leave it on. Turn both off, e.g. as administrator: "+
			`Set-NetIPInterface -InterfaceAlias "%s" -Forwarding Disabled -WeakHostSend Disabled`+
			" (sharing this connection stops working until it is turned on again)", n.Flags, verb, family, n.Interface, n.Interface)
	} else {
		log.Infoln("[TUN] Forwarding/WeakHostSend for %s on %s no longer affects the TUN (%s)", family, n.Interface, clearedText(n.Reason))
	}
	if !eventbus.Enabled(eventbus.TypeTunForwarding) {
		return
	}
	d := eventbus.TunForwarding{
		Interface:    n.Interface,
		Family:       strings.ToLower(family),
		Forwarding:   n.Flags.Forwarding,
		WeakHostSend: n.Flags.WeakHostSend,
		State:        eventbus.TunForwardingOn,
	}
	if !n.On {
		d.State = eventbus.TunForwardingCleared
		d.Reason = n.Reason
	}
	eventbus.Publish(eventbus.TypeTunForwarding, d)
}

func clearedText(reason string) string {
	switch reason {
	case forwardingClearedOff:
		return "turned off"
	case forwardingClearedNotEgress:
		return "the core no longer binds to it"
	case forwardingClearedGone:
		return "the interface is gone"
	case forwardingClearedStopped:
		return "the TUN stopped"
	}
	return reason
}
