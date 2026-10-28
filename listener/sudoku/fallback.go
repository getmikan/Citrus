package sudoku

import (
	"net"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/fallback"
	"github.com/metacubex/mihomo/listener/inner"
)

// relayFallback relays raw to the fallback address under the limits of
// l.fallbacks (fallback.Limiter, fallback.IdleTimeout).
func (l *Listener) relayFallback(wrapper, raw net.Conn, tunnel C.Tunnel, replay bool) {
	defer raw.Close()
	if wrapper != raw {
		defer wrapper.Close()
	}
	r, ok := l.fallbacks.Acquire(raw)
	if !ok {
		return
	}
	defer l.fallbacks.Release(r)
	backend, err := inner.HandleTcp(tunnel, l.fallback, "")
	if err != nil {
		return
	}
	defer backend.Close()
	if !l.fallbacks.Attach(r, backend) {
		return
	}
	_ = raw.SetDeadline(time.Time{})
	_ = backend.SetDeadline(time.Time{})
	idle := fallback.NewIdleGuard(fallback.IdleTimeout, raw, backend)
	defer idle.Stop()
	if replay {
		relayToFallback(wrapper, idle.Wrap(raw), idle.Wrap(backend))
	} else {
		N.Relay(idle.Wrap(wrapper), idle.Wrap(backend))
	}
}
