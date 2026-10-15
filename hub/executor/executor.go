package executor

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "unsafe"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/component/auth"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/eventbus"
	"github.com/metacubex/mihomo/component/geodata"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/keepalive"
	"github.com/metacubex/mihomo/component/profile"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/resource"
	"github.com/metacubex/mihomo/component/sniffer"
	"github.com/metacubex/mihomo/component/trie"
	"github.com/metacubex/mihomo/component/updater"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/hub/metrics"
	"github.com/metacubex/mihomo/listener"
	authStore "github.com/metacubex/mihomo/listener/auth"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/inner"
	"github.com/metacubex/mihomo/listener/tproxy"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp/ntp"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

var mux sync.Mutex

func readConfig(path string) ([]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("configuration file %s is empty", path)
	}

	return data, err
}

// Parse config with default config path
func Parse() (*config.Config, error) {
	return ParseWithPath(C.Path.Config())
}

// ParseWithPath parse config with custom config path
func ParseWithPath(path string) (*config.Config, error) {
	buf, err := readConfig(path)
	if err != nil {
		return nil, err
	}

	return ParseWithBytes(buf)
}

// ParseWithBytes config with buffer
func ParseWithBytes(buf []byte) (*config.Config, error) {
	return config.Parse(buf)
}

// ApplyConfig dispatch configure to all parts without ExternalController
func ApplyConfig(cfg *config.Config, force bool) {
	mux.Lock()
	defer mux.Unlock()
	log.SetLevel(cfg.General.LogLevel)
	log.SetFormat(cfg.General.LogFormat, cfg.General.LogTimestampFormat)

	tunnel.OnSuspend()

	ca.ResetCertificate()
	for _, c := range cfg.TLS.CustomTrustCert {
		if err := ca.AddCertificate(c); err != nil {
			log.Warnln("%s\nadd error: %s", c, err.Error())
		}
	}

	updateExperimental(cfg.Experimental)
	updateMetrics(cfg.Metrics)
	updateUsers(cfg.Users)
	updateProxies(cfg.Proxies, cfg.Providers)
	updateRules(cfg.Rules, cfg.SubRules, cfg.RuleProviders)
	updateSniffer(cfg.Sniffer)
	updateHosts(cfg.Hosts)
	updateGeneral(cfg.General, true)
	updateDNS(cfg.DNS, cfg.General.IPv6)
	updateNTP(cfg.NTP) // initialize NTP after DNS because an NTP server may be a hostname.
	updateListeners(cfg.General, cfg.Listeners, force)
	retireUsers(cfg.Listeners)
	updateUserLimits(cfg.UserLimits)
	updateTun(cfg.General) // tun should not care "force"
	updateIPTables(cfg)
	updateTunnels(cfg.Tunnels)

	tunnel.OnInnerLoading()

	initInnerTcp()
	loadProvider(cfg.Providers)
	closeRemovedWireGuardDevices(cfg.Proxies, cfg.Providers)
	updateProfile(cfg)
	loadProvider(cfg.RuleProviders)
	runtime.GC()
	tunnel.OnRunning()
	updateUpdater(cfg)

	resolver.ResetConnection()
	eventbus.PublishConfigReload(nil)
}

// updateUserLimits replaces the per-user limits with those of the
// configuration; the limits set through the API are dropped, and the quota
// usage of a user that keeps a limit survives.
func updateUserLimits(limits []statistic.UserLimit) {
	if err := statistic.DefaultManager.Users().SetConfigLimits(limits); err != nil {
		log.Errorln("user-limits: %s", err)
	}
}

// retireUsers marks the per-user traffic counters of the listeners and users
// that the new configuration no longer has, so they are dropped once their
// connections are closed and their bytes drained. The built-in inbounds
// (DEFAULT-*) and the listeners that cannot list their users rely on the idle
// timeout instead.
func retireUsers(listeners map[string]C.InboundListener) {
	retireUsersIn(statistic.DefaultManager.Users(), listeners)
}

func retireUsersIn(um *statistic.UserManager, listeners map[string]C.InboundListener) {
	known := make(map[string]map[string]struct{})
	um.Retire(func(key statistic.UserKey) bool {
		if strings.HasPrefix(key.Inbound, "DEFAULT-") {
			return true
		}
		l, ok := listeners[key.Inbound]
		if !ok {
			return false
		}
		lister, ok := l.(C.InboundUserLister)
		if !ok {
			return true
		}
		users, ok := known[key.Inbound]
		if !ok {
			users = make(map[string]struct{})
			for _, user := range lister.InboundUsers() {
				users[user] = struct{}{}
			}
			known[key.Inbound] = users
		}
		_, ok = users[key.User]
		return ok
	})
}

func initInnerTcp() {
	inner.New(tunnel.Tunnel)
}

func GetGeneral() *config.General {
	ports := listener.GetPorts()
	var authenticator []string
	if auth := authStore.Default.Authenticator(); auth != nil {
		authenticator = auth.Users()
	}

	general := &config.General{
		Inbound: config.Inbound{
			Port:              ports.Port,
			SocksPort:         ports.SocksPort,
			RedirPort:         ports.RedirPort,
			TProxyPort:        ports.TProxyPort,
			MixedPort:         ports.MixedPort,
			Tun:               listener.GetTunConf(),
			TuicServer:        listener.GetTuicConf(),
			ShadowSocksConfig: ports.ShadowSocksConfig,
			Authentication:    authenticator,
			SkipAuthPrefixes:  inbound.SkipAuthPrefixes(),
			LanAllowedIPs:     inbound.AllowedIPs(),
			LanDisAllowedIPs:  inbound.DisAllowedIPs(),
			AllowLan:          listener.AllowLan(),
			BindAddress:       listener.BindAddress(),
			InboundTfo:        inbound.Tfo(),
			InboundMPTCP:      inbound.MPTCP(),
		},
		Mode:         tunnel.Mode(),
		UnifiedDelay: adapter.UnifiedDelay.Load(),
		LogLevel:     log.Level(),
		IPv6:         !resolver.DisableIPv6,
		Interface:    dialer.DefaultInterface.Load(),
		RoutingMark:  int(dialer.DefaultRoutingMark.Load()),
		GeoXUrl: config.GeoXUrl{
			GeoIp:   geodata.GeoIpUrl(),
			Mmdb:    geodata.MmdbUrl(),
			ASN:     geodata.ASNUrl(),
			GeoSite: geodata.GeoSiteUrl(),
		},
		GeoAutoUpdate:     updater.GeoAutoUpdate(),
		GeoUpdateInterval: updater.GeoUpdateInterval(),
		GeodataMode:       geodata.GeodataMode(),
		GeodataLoader:     geodata.LoaderName(),
		GeositeMatcher:    geodata.SiteMatcherName(),
		TCPConcurrent:     dialer.GetTcpConcurrent(),
		TCPConnectTimeout: tunnel.TCPConnectTimeout().Milliseconds(),
		FindProcessMode:   tunnel.FindProcessMode(),
		Sniffing:          tunnel.IsSniffing(),
		GlobalUA:          mihomoHttp.UA(),
		ETagSupport:       resource.ETag(),
		KeepAliveInterval: int(keepalive.KeepAliveInterval() / time.Second),
		KeepAliveIdle:     int(keepalive.KeepAliveIdle() / time.Second),
		DisableKeepAlive:  keepalive.DisableKeepAlive(),
		UserStats:         statistic.UserStatsEnabled(),
	}
	general.LogFormat, general.LogTimestampFormat = log.Format()

	return general
}

// updateListeners applies the listeners of the configuration. The access
// policy of the built-in listeners (allow-lan, bind-address,
// skip-auth-prefixes, lan-allowed-ips, lan-disallowed-ips) and the built-in
// ShadowSocks and TUIC servers, with their credentials, always come from the
// new configuration: a reload that tightens them must not leave the old ones
// in force. Without force the built-in http, socks, redir, tproxy and mixed
// listeners keep the ports they run on (a client may have changed them with
// PATCH /configs); they are still rebound when allow-lan or bind-address
// changed.
func updateListeners(general *config.General, listeners map[string]C.InboundListener, force bool) {
	listener.PatchInboundListeners(listeners, tunnel.Tunnel, true)

	inbound.SetSkipAuthPrefixes(general.SkipAuthPrefixes)
	inbound.SetAllowedIPs(general.LanAllowedIPs)
	inbound.SetDisAllowedIPs(general.LanDisAllowedIPs)
	listener.SetAllowLan(general.AllowLan)
	listener.SetBindAddress(general.BindAddress)

	port, socksPort, redirPort, tproxyPort, mixedPort := general.Port, general.SocksPort, general.RedirPort, general.TProxyPort, general.MixedPort
	if !force {
		ports := listener.GetPorts()
		port, socksPort, redirPort, tproxyPort, mixedPort = ports.Port, ports.SocksPort, ports.RedirPort, ports.TProxyPort, ports.MixedPort
	}
	listener.ReCreateHTTP(port, tunnel.Tunnel)
	listener.ReCreateSocks(socksPort, tunnel.Tunnel)
	listener.ReCreateRedir(redirPort, tunnel.Tunnel)
	listener.ReCreateTProxy(tproxyPort, tunnel.Tunnel)
	listener.ReCreateMixed(mixedPort, tunnel.Tunnel)
	listener.ReCreateShadowSocks(general.ShadowSocksConfig, tunnel.Tunnel)
	listener.ReCreateTuic(general.TuicServer, tunnel.Tunnel)
}

func updateMetrics(c *config.Metrics) {
	if c == nil {
		c = &config.Metrics{}
	}
	metrics.SetOptions(metrics.Options{Enable: c.Enable, PerUser: c.PerUser, HealthWithoutAuth: c.HealthWithoutAuth})
}

func updateTun(general *config.General) {
	listener.ReCreateTun(general.Tun, tunnel.Tunnel)
}

func updateExperimental(c *config.Experimental) {
	if c.QUICGoDisableGSO {
		_ = os.Setenv("QUIC_GO_DISABLE_GSO", strconv.FormatBool(true))
	}
	if c.QUICGoDisableECN {
		_ = os.Setenv("QUIC_GO_DISABLE_ECN", strconv.FormatBool(true))
	}
	resolver.SetIP4PEnable(c.IP4PEnable)
}

func updateNTP(c *config.NTP) {
	if c.Enable {
		ntp.ReCreateNTPService(
			net.JoinHostPort(c.Server, strconv.Itoa(c.Port)),
			time.Duration(c.Interval),
			c.DialerProxy,
			tunnel.Tunnel,
			c.WriteToSystem,
		)
	} else {
		ntp.ReCreateNTPService("", 0, "", nil, false)
	}
}

func updateDNS(c *config.DNS, generalIPv6 bool) {
	if !c.Enable {
		resolver.DefaultResolver = nil
		resolver.DefaultHostMapper = nil
		resolver.DefaultService = nil
		resolver.ProxyServerHostResolver = nil
		resolver.DirectHostResolver = nil
		dns.ReCreateServer("", nil, nil)
		return
	}

	ipv6 := c.IPv6 && generalIPv6
	r := dns.NewResolver(dns.Config{
		Main:                 c.NameServer,
		Fallback:             c.Fallback,
		IPv6:                 ipv6,
		IPv6Timeout:          c.IPv6Timeout,
		FallbackIPFilter:     c.FallbackIPFilter,
		FallbackDomainFilter: c.FallbackDomainFilter,
		FallbackLazyQuery:    c.FallbackLazyQuery,
		Default:              c.DefaultNameserver,
		Policy:               c.NameServerPolicy,
		ProxyServer:          c.ProxyServerNameserver,
		ProxyServerPolicy:    c.ProxyServerPolicy,
		DirectServer:         c.DirectNameServer,
		DirectFollowPolicy:   c.DirectFollowPolicy,
		CacheAlgorithm:       c.CacheAlgorithm,
		CacheMaxSize:         c.CacheMaxSize,

		ServeExpired:              c.ServeExpired,
		ServeExpiredTTL:           c.ServeExpiredTTL,
		ServeExpiredClientTimeout: c.ServeExpiredClientTimeout,
	})
	m := dns.NewEnhancer(dns.EnhancerConfig{
		IPv6:          ipv6,
		EnhancedMode:  c.EnhancedMode,
		FakeIPPool:    c.FakeIPPool,
		FakeIPPool6:   c.FakeIPPool6,
		FakeIPSkipper: c.FakeIPSkipper,
		FakeIPTTL:     c.FakeIPTTL,
		UseHosts:      c.UseHosts,
	})

	// reuse cache of old host mapper
	if old := resolver.DefaultHostMapper; old != nil {
		m.PatchFrom(old.(*dns.ResolverEnhancer))
	}

	s := dns.NewService(r, m)

	resolver.DefaultResolver = r
	resolver.DefaultHostMapper = m
	resolver.DefaultService = s
	resolver.UseSystemHosts = c.UseSystemHosts

	if r.ProxyResolver.Invalid() {
		resolver.ProxyServerHostResolver = r.ProxyResolver
	} else {
		resolver.ProxyServerHostResolver = r.Resolver
	}

	if r.DirectResolver.Invalid() {
		resolver.DirectHostResolver = r.DirectResolver
	} else {
		resolver.DirectHostResolver = r.Resolver
	}

	lc := inbound.NewListenConfig()
	lc.SetRouteMark(c.ListenRoutingMark)
	dns.ReCreateServer(c.Listen, lc, s)
}

func updateHosts(tree *trie.DomainTrie[resolver.HostValue]) {
	resolver.DefaultHosts = resolver.NewHosts(tree)
}

func updateProxies(proxies map[string]C.Proxy, providers map[string]P.ProxyProvider) {
	tunnel.UpdateProxies(proxies, providers)
}

// closeRemovedWireGuardDevices closes the devices of the WireGuard proxies that the new
// config no longer has. A replaced proxy closes the old device itself when it starts.
func closeRemovedWireGuardDevices(proxies map[string]C.Proxy, providers map[string]P.ProxyProvider) {
	serial := outbound.WireGuardSerial()
	current := make([]C.Proxy, 0, len(proxies))
	for _, proxy := range proxies {
		current = append(current, proxy)
	}
	for _, pd := range providers {
		current = append(current, pd.Proxies()...)
	}
	outbound.CloseWireGuardDevicesExcept(serial, current)
}

func updateRules(rules []C.Rule, subRules map[string][]C.Rule, ruleProviders map[string]P.RuleProvider) {
	tunnel.UpdateRules(rules, subRules, ruleProviders)
}

func loadProvider[T P.Provider](providers map[string]T) {
	load := func(pv T) {
		name := pv.Name()
		if pv.VehicleType() == P.Compatible {
			log.Infoln("Start initial compatible provider %s", name)
		} else {
			log.Infoln("Start initial provider %s", name)
		}

		if err := pv.Initial(); err != nil {
			switch pv.Type() {
			case P.Proxy:
				{
					log.Errorln("initial proxy provider %s error: %v", name, err)
				}
			case P.Rule:
				{
					log.Errorln("initial rule provider %s error: %v", name, err)
				}
			}
		}
	}

	wg := sync.WaitGroup{}
	ch := make(chan struct{}, concurrentCount)
	for _, pv := range providers {
		pv := pv
		wg.Add(1)
		ch <- struct{}{}
		go func() {
			defer func() { <-ch; wg.Done() }()
			load(pv)
		}()
	}
	wg.Wait()
}

func updateSniffer(snifferConfig *sniffer.Config) {
	dispatcher, err := sniffer.NewDispatcher(snifferConfig)
	if err != nil {
		log.Warnln("initial sniffer failed, err:%v", err)
	}

	tunnel.UpdateSniffer(dispatcher)

	if snifferConfig.Enable {
		log.Infoln("Sniffer is loaded and working")
	} else {
		log.Infoln("Sniffer is closed")
	}
}

func updateTunnels(tunnels []LC.Tunnel) {
	listener.PatchTunnel(tunnels, tunnel.Tunnel)
}

func updateUpdater(cfg *config.Config) {
	general := cfg.General
	updater.SetGeoAutoUpdate(general.GeoAutoUpdate)
	updater.SetGeoUpdateInterval(general.GeoUpdateInterval)

	controller := cfg.Controller
	updater.DefaultUiUpdater = updater.NewUiUpdater(controller.ExternalUI, controller.ExternalUIURL, controller.ExternalUIName)
	updater.DefaultUiUpdater.AutoDownloadUI()
}

//go:linkname temporaryUpdateGeneral github.com/metacubex/mihomo/config.temporaryUpdateGeneral
func temporaryUpdateGeneral(general *config.General) func() {
	oldGeneral := GetGeneral()
	updateGeneral(general, false)
	return func() {
		updateGeneral(oldGeneral, false)
	}
}

func updateGeneral(general *config.General, logging bool) {
	tunnel.SetMode(general.Mode)
	tunnel.SetFindProcessMode(general.FindProcessMode)
	resolver.DisableIPv6 = !general.IPv6

	dialer.SetTcpConcurrent(general.TCPConcurrent)
	_ = tunnel.SetTCPConnectTimeout(general.TCPConnectTimeout)
	if logging && general.TCPConcurrent {
		log.Infoln("Use tcp concurrent")
	}

	inbound.SetTfo(general.InboundTfo)
	inbound.SetMPTCP(general.InboundMPTCP)

	keepalive.SetKeepAliveIdle(time.Duration(general.KeepAliveIdle) * time.Second)
	keepalive.SetKeepAliveInterval(time.Duration(general.KeepAliveInterval) * time.Second)
	keepalive.SetDisableKeepAlive(general.DisableKeepAlive)

	adapter.UnifiedDelay.Store(general.UnifiedDelay)
	statistic.SetUserStatsEnabled(general.UserStats)

	dialer.DefaultInterface.Store(general.Interface)
	dialer.DefaultRoutingMark.Store(int32(general.RoutingMark))
	if logging && general.RoutingMark > 0 {
		log.Infoln("Use routing mark: %#x", general.RoutingMark)
	}

	iface.FlushCache()

	geodata.SetGeodataMode(general.GeodataMode)
	geodata.SetLoader(general.GeodataLoader)
	geodata.SetSiteMatcher(general.GeositeMatcher)
	geodata.SetGeoIpUrl(general.GeoXUrl.GeoIp)
	geodata.SetGeoSiteUrl(general.GeoXUrl.GeoSite)
	geodata.SetMmdbUrl(general.GeoXUrl.Mmdb)
	geodata.SetASNUrl(general.GeoXUrl.ASN)
	mihomoHttp.SetUA(general.GlobalUA)
	resource.SetETag(general.ETagSupport)
}

func updateUsers(users []auth.AuthUser) {
	authenticator := auth.NewAuthenticator(users)
	authStore.Default.SetAuthenticator(authenticator)
	if authenticator != nil {
		log.Infoln("Authentication of local server updated")
	}
}

func updateProfile(cfg *config.Config) {
	profileCfg := cfg.Profile

	profile.StoreSelected.Store(profileCfg.StoreSelected)
	if profileCfg.StoreSelected {
		patchSelectGroup(cfg.Proxies)
	}
}

func patchSelectGroup(proxies map[string]C.Proxy) {
	mapping := cachefile.Cache().SelectedMap()
	if mapping == nil {
		return
	}

	for name, outbound := range proxies {
		selector, ok := outbound.Adapter().(outboundgroup.SelectAble)
		if !ok {
			continue
		}

		selected, exist := mapping[name]
		if !exist {
			continue
		}

		selector.ForceSet(selected)
	}
}

func updateIPTables(cfg *config.Config) {
	tproxy.CleanupTProxyIPTables()

	iptables := cfg.IPTables
	if runtime.GOOS != "linux" || !iptables.Enable {
		return
	}

	var err error
	defer func() {
		if err != nil {
			log.Errorln("[IPTABLES] setting iptables failed: %s", err.Error())
			os.Exit(2)
		}
	}()

	if cfg.General.Tun.Enable {
		err = fmt.Errorf("when tun is enabled, iptables cannot be set automatically")
		return
	}

	var (
		inboundInterface = "lo"
		bypass           = iptables.Bypass
		tProxyPort       = cfg.General.TProxyPort
		dnsCfg           = cfg.DNS
		DnsRedirect      = iptables.DnsRedirect

		dnsPort netip.AddrPort
	)

	if tProxyPort == 0 {
		err = fmt.Errorf("tproxy-port must be greater than zero")
		return
	}

	if DnsRedirect {
		if !dnsCfg.Enable {
			err = fmt.Errorf("DNS server must be enable")
			return
		}

		dnsPort, err = netip.ParseAddrPort(dnsCfg.Listen)
		if err != nil {
			err = fmt.Errorf("DNS server must be correct")
			return
		}
	}

	if iptables.InboundInterface != "" {
		inboundInterface = iptables.InboundInterface
	}

	dialer.DefaultRoutingMark.CompareAndSwap(0, 2158)

	err = tproxy.SetTProxyIPTables(inboundInterface, bypass, uint16(tProxyPort), DnsRedirect, dnsPort.Port())
	if err != nil {
		return
	}

	log.Infoln("[IPTABLES] Setting iptables completed")
}

func Shutdown() {
	listener.Cleanup()
	tproxy.CleanupTProxyIPTables()
	resolver.StoreFakePoolState()

	log.Warnln("Citrus shutting down")
}
