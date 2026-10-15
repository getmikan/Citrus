package listener

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/eventbus"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/http"
	"github.com/metacubex/mihomo/listener/mixed"
	"github.com/metacubex/mihomo/listener/redir"
	embedSS "github.com/metacubex/mihomo/listener/shadowsocks"
	"github.com/metacubex/mihomo/listener/sing_shadowsocks"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/listener/socks"
	"github.com/metacubex/mihomo/listener/tproxy"
	"github.com/metacubex/mihomo/listener/tuic"
	LT "github.com/metacubex/mihomo/listener/tunnel"
	"github.com/metacubex/mihomo/log"

	"github.com/samber/lo"
)

var (
	allowLan    = false
	bindAddress = "*"

	socksListener       *socks.Listener
	socksUDPListener    *socks.UDPListener
	httpListener        *http.Listener
	redirListener       *redir.Listener
	redirUDPListener    *tproxy.UDPListener
	tproxyListener      *tproxy.Listener
	tproxyUDPListener   *tproxy.UDPListener
	mixedListener       *mixed.Listener
	mixedUDPLister      *socks.UDPListener
	tunnelTCPListeners  = map[string]*LT.Listener{}
	tunnelUDPListeners  = map[string]*LT.PacketConn{}
	inboundListeners    = map[string]C.InboundListener{}
	runtimeUsers        = map[string]struct{}{} // listeners whose users changed at runtime
	failedListeners     = map[string]struct{}{} // listeners of the configuration that failed to listen
	tunLister           *sing_tun.Listener
	shadowSocksListener C.MultiAddrListener
	tuicListener        *tuic.Listener

	// lock for recreate function
	socksMux   sync.Mutex
	httpMux    sync.Mutex
	redirMux   sync.Mutex
	tproxyMux  sync.Mutex
	mixedMux   sync.Mutex
	tunnelMux  sync.Mutex
	inboundMux sync.Mutex
	tunMux     sync.Mutex
	ssMux      sync.Mutex
	tuicMux    sync.Mutex

	LastTunConf  LC.Tun
	LastTuicConf LC.TuicServer
)

type Ports struct {
	Port              int    `json:"port"`
	SocksPort         int    `json:"socks-port"`
	RedirPort         int    `json:"redir-port"`
	TProxyPort        int    `json:"tproxy-port"`
	MixedPort         int    `json:"mixed-port"`
	ShadowSocksConfig string `json:"ss-config"`
}

func GetTunConf() LC.Tun {
	if tunLister == nil {
		return LastTunConf
	}
	return tunLister.Config()
}

func GetTuicConf() LC.TuicServer {
	if tuicListener == nil {
		return LC.TuicServer{Enable: false}
	}
	return tuicListener.Config()
}

func AllowLan() bool {
	return allowLan
}

func BindAddress() string {
	return bindAddress
}

func SetAllowLan(al bool) {
	allowLan = al
}

func SetBindAddress(host string) {
	bindAddress = host
}

func ReCreateHTTP(port int, tunnel C.Tunnel) {
	httpMux.Lock()
	defer httpMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start HTTP server error: %s", err.Error())
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	if httpListener != nil {
		if httpListener.RawAddress() == addr {
			return
		}
		httpListener.Close()
		httpListener = nil
	}

	if portIsZero(addr) {
		return
	}

	httpListener, err = http.New(addr, tunnel)
	if err != nil {
		log.Errorln("Start HTTP server error: %s", err.Error())
		return
	}

	log.Infoln("HTTP proxy listening at: %s", httpListener.Address())
}

func ReCreateSocks(port int, tunnel C.Tunnel) {
	socksMux.Lock()
	defer socksMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start SOCKS server error: %s", err.Error())
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	shouldTCPIgnore := false
	shouldUDPIgnore := false

	if socksListener != nil {
		if socksListener.RawAddress() != addr {
			socksListener.Close()
			socksListener = nil
		} else {
			shouldTCPIgnore = true
		}
	}

	if socksUDPListener != nil {
		if socksUDPListener.RawAddress() != addr {
			socksUDPListener.Close()
			socksUDPListener = nil
		} else {
			shouldUDPIgnore = true
		}
	}

	if shouldTCPIgnore && shouldUDPIgnore {
		return
	}

	if portIsZero(addr) {
		return
	}

	tcpListener, err := socks.New(addr, tunnel)
	if err != nil {
		return
	}

	udpListener, err := socks.NewUDP(addr, tunnel)
	if err != nil {
		tcpListener.Close()
		return
	}

	socksListener = tcpListener
	socksUDPListener = udpListener

	log.Infoln("SOCKS proxy listening at: %s", socksListener.Address())
}

func ReCreateRedir(port int, tunnel C.Tunnel) {
	redirMux.Lock()
	defer redirMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start Redir server error: %s", err.Error())
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	if redirListener != nil {
		if redirListener.RawAddress() == addr {
			return
		}
		redirListener.Close()
		redirListener = nil
	}

	if redirUDPListener != nil {
		if redirUDPListener.RawAddress() == addr {
			return
		}
		redirUDPListener.Close()
		redirUDPListener = nil
	}

	if portIsZero(addr) {
		return
	}

	redirListener, err = redir.New(addr, tunnel)
	if err != nil {
		return
	}

	redirUDPListener, err = tproxy.NewUDP(addr, tunnel)
	if err != nil {
		log.Warnln("Failed to start Redir UDP Listener: %s", err)
	}

	log.Infoln("Redirect proxy listening at: %s", redirListener.Address())
}

func ReCreateShadowSocks(shadowSocksConfig string, tunnel C.Tunnel) {
	ssMux.Lock()
	defer ssMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start ShadowSocks server error: %s", err.Error())
		}
	}()

	var ssConfig LC.ShadowsocksServer
	if addr, cipher, password, err := embedSS.ParseSSURL(shadowSocksConfig); err == nil {
		ssConfig = LC.ShadowsocksServer{
			Enable:   len(shadowSocksConfig) > 0,
			Listen:   addr,
			Password: password,
			Cipher:   cipher,
			Udp:      true,
		}
	}

	shouldIgnore := false

	if shadowSocksListener != nil {
		if shadowSocksListener.Config() != ssConfig.String() {
			shadowSocksListener.Close()
			shadowSocksListener = nil
		} else {
			shouldIgnore = true
		}
	}

	if shouldIgnore {
		return
	}

	if !ssConfig.Enable {
		return
	}

	listener, err := sing_shadowsocks.New(ssConfig, inbound.NewListenConfig(), tunnel)
	if err != nil {
		return
	}

	shadowSocksListener = listener

	for _, addr := range shadowSocksListener.AddrList() {
		log.Infoln("ShadowSocks proxy listening at: %s", addr.String())
	}
	return
}

func ReCreateTuic(config LC.TuicServer, tunnel C.Tunnel) {
	tuicMux.Lock()
	defer func() {
		LastTuicConf = config
		tuicMux.Unlock()
	}()
	shouldIgnore := false

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start Tuic server error: %s", err.Error())
		}
	}()

	if tuicListener != nil {
		if tuicListener.Config().String() != config.String() {
			tuicListener.Close()
			tuicListener = nil
		} else {
			shouldIgnore = true
		}
	}

	if shouldIgnore {
		return
	}

	if !config.Enable {
		return
	}

	listener, err := tuic.New(config, inbound.NewListenConfig(), tunnel)
	if err != nil {
		return
	}

	tuicListener = listener

	for _, addr := range tuicListener.AddrList() {
		log.Infoln("Tuic proxy listening at: %s", addr.String())
	}
	return
}

func ReCreateTProxy(port int, tunnel C.Tunnel) {
	tproxyMux.Lock()
	defer tproxyMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start TProxy server error: %s", err.Error())
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	if tproxyListener != nil {
		if tproxyListener.RawAddress() == addr {
			return
		}
		tproxyListener.Close()
		tproxyListener = nil
	}

	if tproxyUDPListener != nil {
		if tproxyUDPListener.RawAddress() == addr {
			return
		}
		tproxyUDPListener.Close()
		tproxyUDPListener = nil
	}

	if portIsZero(addr) {
		return
	}

	tproxyListener, err = tproxy.New(addr, tunnel)
	if err != nil {
		return
	}

	tproxyUDPListener, err = tproxy.NewUDP(addr, tunnel)
	if err != nil {
		log.Warnln("Failed to start TProxy UDP Listener: %s", err)
	}

	log.Infoln("TProxy server listening at: %s", tproxyListener.Address())
}

func ReCreateMixed(port int, tunnel C.Tunnel) {
	mixedMux.Lock()
	defer mixedMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start Mixed(http+socks) server error: %s", err.Error())
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	shouldTCPIgnore := false
	shouldUDPIgnore := false

	if mixedListener != nil {
		if mixedListener.RawAddress() != addr {
			mixedListener.Close()
			mixedListener = nil
		} else {
			shouldTCPIgnore = true
		}
	}
	if mixedUDPLister != nil {
		if mixedUDPLister.RawAddress() != addr {
			mixedUDPLister.Close()
			mixedUDPLister = nil
		} else {
			shouldUDPIgnore = true
		}
	}

	if shouldTCPIgnore && shouldUDPIgnore {
		return
	}

	if portIsZero(addr) {
		return
	}

	mixedListener, err = mixed.New(addr, tunnel)
	if err != nil {
		return
	}

	mixedUDPLister, err = socks.NewUDP(addr, tunnel)
	if err != nil {
		mixedListener.Close()
		return
	}

	log.Infoln("Mixed(http+socks) proxy listening at: %s", mixedListener.Address())
}

func ReCreateTun(tunConf LC.Tun, tunnel C.Tunnel) {
	tunConf.Sort()

	tunMux.Lock()
	defer func() {
		LastTunConf = tunConf
		tunMux.Unlock()
	}()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start TUN listening error: %s", err.Error())
			tunConf.Enable = false
		}
	}()

	if tunConf.Equal(LastTunConf) {
		if tunLister != nil { // some default value in dialer maybe changed when config reload, reset at here
			tunLister.OnReload()
		}
		return
	}

	closeTunListener()

	if !tunConf.Enable {
		return
	}

	lister, err := sing_tun.New(tunConf, tunnel)
	if err != nil {
		return
	}
	tunLister = lister

	log.Infoln("[TUN] Tun adapter listening at: %s", tunLister.Address())
}

func PatchTunnel(tunnels []LC.Tunnel, tunnel C.Tunnel) {
	tunnelMux.Lock()
	defer tunnelMux.Unlock()

	type addrProxy struct {
		network string
		addr    string
		target  string
		proxy   string
	}

	tcpOld := lo.Map(
		lo.Keys(tunnelTCPListeners),
		func(key string, _ int) addrProxy {
			parts := strings.Split(key, "/")
			return addrProxy{
				network: "tcp",
				addr:    parts[0],
				target:  parts[1],
				proxy:   parts[2],
			}
		},
	)
	udpOld := lo.Map(
		lo.Keys(tunnelUDPListeners),
		func(key string, _ int) addrProxy {
			parts := strings.Split(key, "/")
			return addrProxy{
				network: "udp",
				addr:    parts[0],
				target:  parts[1],
				proxy:   parts[2],
			}
		},
	)
	oldElm := lo.Union(tcpOld, udpOld)

	newElm := lo.FlatMap(
		tunnels,
		func(tunnel LC.Tunnel, _ int) []addrProxy {
			return lo.Map(
				tunnel.Network,
				func(network string, _ int) addrProxy {
					return addrProxy{
						network: network,
						addr:    tunnel.Address,
						target:  tunnel.Target,
						proxy:   tunnel.Proxy,
					}
				},
			)
		},
	)

	needClose, needCreate := lo.Difference(oldElm, newElm)

	for _, elm := range needClose {
		key := fmt.Sprintf("%s/%s/%s", elm.addr, elm.target, elm.proxy)
		if elm.network == "tcp" {
			tunnelTCPListeners[key].Close()
			delete(tunnelTCPListeners, key)
		} else {
			tunnelUDPListeners[key].Close()
			delete(tunnelUDPListeners, key)
		}
	}

	lc := inbound.NewListenConfig()
	for _, elm := range needCreate {
		key := fmt.Sprintf("%s/%s/%s", elm.addr, elm.target, elm.proxy)
		if elm.network == "tcp" {
			l, err := LT.New(elm.addr, elm.target, elm.proxy, lc, tunnel)
			if err != nil {
				log.Errorln("Start tunnel %s error: %s", elm.target, err.Error())
				continue
			}
			tunnelTCPListeners[key] = l
			log.Infoln("Tunnel(tcp/%s) proxy %s listening at: %s", elm.target, elm.proxy, tunnelTCPListeners[key].Address())
		} else {
			l, err := LT.NewUDP(elm.addr, elm.target, elm.proxy, lc, tunnel)
			if err != nil {
				log.Errorln("Start tunnel %s error: %s", elm.target, err.Error())
				continue
			}
			tunnelUDPListeners[key] = l
			log.Infoln("Tunnel(udp/%s) proxy %s listening at: %s", elm.target, elm.proxy, tunnelUDPListeners[key].Address())
		}
	}
}

func PatchInboundListeners(newListenerMap map[string]C.InboundListener, tunnel C.Tunnel, dropOld bool) {
	inboundMux.Lock()
	defer inboundMux.Unlock()

	for name, newListener := range newListenerMap {
		if oldListener, ok := inboundListeners[name]; ok {
			if updateUsersInPlace(name, oldListener, newListener) {
				continue
			}
			_ = oldListener.Close()
			delete(runtimeUsers, name)
			publishInboundState(name, oldListener, eventbus.InboundStopped, nil)
		}
		if err := newListener.Listen(tunnel); err != nil {
			log.Errorln("Listener %s listen err: %s", name, err.Error())
			failedListeners[name] = struct{}{}
			publishInboundState(name, newListener, eventbus.InboundFailed, err)
			continue
		}
		delete(failedListeners, name)
		inboundListeners[name] = newListener
		publishInboundState(name, newListener, eventbus.InboundStarted, nil)
	}

	if dropOld {
		for name := range failedListeners {
			if _, ok := newListenerMap[name]; !ok {
				delete(failedListeners, name)
			}
		}
		for name, oldListener := range inboundListeners {
			if _, ok := newListenerMap[name]; !ok {
				_ = oldListener.Close()
				delete(inboundListeners, name)
				delete(runtimeUsers, name)
				publishInboundState(name, oldListener, eventbus.InboundStopped, nil)
			}
		}
	}
}

// publishInboundState reports a listener of the `listeners:` section that
// started, failed to listen or stopped.
func publishInboundState(name string, l C.InboundListener, state string, err error) {
	if !eventbus.Enabled(eventbus.TypeInboundState) {
		return
	}
	d := eventbus.InboundState{Inbound: name, Type: inboundTypeOf(l), State: state}
	if err != nil {
		d.Error = err.Error()
	}
	eventbus.Publish(eventbus.TypeInboundState, d)
}

// FailedInboundListeners returns the number of listeners of the last applied
// configuration that failed to listen (the port is taken, a certificate is
// missing and so on); readiness requires it to be zero.
func FailedInboundListeners() int {
	inboundMux.Lock()
	defer inboundMux.Unlock()
	return len(failedListeners)
}

// updateUsersInPlace reports whether oldListener can stay for newListener:
// when their configurations are equal, or differ only in the users and
// oldListener takes the users of the new configuration in place. The users
// changed at runtime are replaced by those of the configuration as well.
// When it reports false, oldListener must be closed and newListener started.
func updateUsersInPlace(name string, oldListener, newListener C.InboundListener) bool {
	equal := oldListener.Config().Equal(newListener.Config())
	_, touched := runtimeUsers[name]
	oldUpdater, ok := oldListener.(C.InboundUserUpdater)
	if !ok || (equal && !touched) {
		return equal
	}
	newUpdater, ok := newListener.(C.InboundUserUpdater)
	if !ok || !(equal || oldUpdater.SameExceptUsers(newListener.Config())) {
		return false
	}
	users := newUpdater.Users() // the users of the configuration: it does not listen
	if !sameUsers(oldUpdater.Users(), users) {
		if err := oldUpdater.SetUsers(users); err != nil {
			log.Warnln("Listener %s: cannot set the users in place, recreating it: %s", name, err)
			return false
		}
		log.Infoln("Listener %s: users updated in place", name)
	}
	delete(runtimeUsers, name)
	return true
}

// GetPorts return the ports of proxy servers
func GetPorts() *Ports {
	ports := &Ports{}

	if httpListener != nil {
		_, portStr, _ := net.SplitHostPort(httpListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.Port = port
	}

	if socksListener != nil {
		_, portStr, _ := net.SplitHostPort(socksListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.SocksPort = port
	}

	if redirListener != nil {
		_, portStr, _ := net.SplitHostPort(redirListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.RedirPort = port
	}

	if tproxyListener != nil {
		_, portStr, _ := net.SplitHostPort(tproxyListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.TProxyPort = port
	}

	if mixedListener != nil {
		_, portStr, _ := net.SplitHostPort(mixedListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.MixedPort = port
	}

	if shadowSocksListener != nil {
		ports.ShadowSocksConfig = shadowSocksListener.Config()
	}

	return ports
}

func portIsZero(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if port == "0" || port == "" || err != nil {
		return true
	}
	return false
}

func genAddr(host string, port int, allowLan bool) string {
	if allowLan {
		if host == "*" {
			return fmt.Sprintf(":%d", port)
		}
		return fmt.Sprintf("%s:%d", host, port)
	}

	return fmt.Sprintf("127.0.0.1:%d", port)
}

func closeTunListener() {
	if tunLister != nil {
		tunLister.Close()
		tunLister = nil
	}
}

func Cleanup() {
	closeTunListener()
}
