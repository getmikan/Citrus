package ntp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/ntp"
)

var globalSrv *Service
var globalMu sync.Mutex

type Service struct {
	server         M.Socksaddr
	dialer         proxydialer.SingDialer
	ticker         *time.Ticker
	ctx            context.Context
	cancel         context.CancelFunc
	syncSystemTime bool
	guard          stepGuard
}

func ReCreateNTPService(server string, interval time.Duration, dialerProxy string, tunnel C.Tunnel, syncSystemTime bool) {
	globalMu.Lock()
	defer globalMu.Unlock()
	if globalSrv != nil {
		globalSrv.Stop()
	}
	if server == "" || interval <= 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	var cDialer C.Dialer = dialer.NewDialer()
	if dialerProxy != "" {
		cDialer = proxydialer.NewByName(dialerProxy, tunnel)
	}
	globalSrv = &Service{
		server:         M.ParseSocksaddr(server),
		dialer:         proxydialer.NewSingDialer(cDialer),
		ticker:         time.NewTicker(interval * time.Minute),
		ctx:            ctx,
		cancel:         cancel,
		syncSystemTime: syncSystemTime,
	}
	globalSrv.Start()
}

func (srv *Service) Start() {
	log.Infoln("NTP service start, sync system time is %t", srv.syncSystemTime)
	go srv.loopUpdate()
}

func (srv *Service) Stop() {
	log.Infoln("NTP service stop")
	srv.cancel()
}

func (srv *Service) update() error {
	var err error
	// Retry network failures, but never treat repeated answers from the same
	// unauthenticated source as independent confirmation of a large step.
	for i := 0; i < 3; i++ {
		if i > 0 {
			select {
			case <-srv.ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
			}
		}
		var response *ntp.Response
		response, err = ntp.Exchange(srv.ctx, srv.dialer, srv.server)
		if err != nil {
			if srv.ctx.Err() != nil {
				return nil
			}
			continue
		}
		offset := response.ClockOffset
		now := time.Now()
		ok, step := srv.guard.check(now, now.Add(offset))
		if !ok {
			if srv.syncSystemTime && !srv.guard.synced {
				// This path is reachable only after the configuration parser's
				// allow-unsafe-write-to-system opt-in. It preserves RTC-less
				// bootstrap compatibility without feeding the offset directly to
				// TLS/protocol clocks.
				if syncErr := setSystemTime(response.Time); syncErr != nil {
					return fmt.Errorf("unsafe bootstrap system-clock write: %w", syncErr)
				}
				srv.guard.accept(now, now.Add(offset))
				log.Warnln("Applied explicitly allowed unauthenticated initial system-clock step of %s", step)
				return nil
			}
			log.Warnln("NTP answer from %s would move the clock by %s; refusing unauthenticated large step", srv.server, step)
			err = fmt.Errorf("unsafe unauthenticated clock step of %s", step)
			continue
		}
		if offset > time.Duration(0) {
			log.Infoln("System clock is ahead of NTP time by %s", offset)
		} else if offset < time.Duration(0) {
			log.Infoln("System clock is behind NTP time by %s", -offset)
		}
		// TLS and protocol freshness remain bound to the operating-system clock.
		if srv.syncSystemTime {
			timeNow := response.Time
			syncErr := setSystemTime(timeNow)
			if syncErr == nil {
				log.Infoln("Sync system time success: %s", timeNow.Local().Format(ntp.TimeLayout))
			} else {
				log.Errorln("Write time to system: %s", syncErr)
				srv.syncSystemTime = false
			}
		}
		return nil
	}
	return err
}

func (srv *Service) loopUpdate() {
	defer srv.ticker.Stop()
	for {
		err := srv.update()
		if err != nil {
			log.Warnln("Sync time failed: %s", err)
		}
		select {
		case <-srv.ctx.Done():
			return
		case <-srv.ticker.C:
		}
	}
}
