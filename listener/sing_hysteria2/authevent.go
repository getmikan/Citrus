package sing_hysteria2

import (
	"net"
	"strconv"

	"github.com/metacubex/mihomo/component/authevent"

	"github.com/metacubex/http"
)

// The Hysteria 2 authentication request, as sing-quic's internal protocol
// package defines it.
const (
	authHost     = "hysteria"
	authPath     = "/auth"
	authHeader   = "Hysteria-Auth"
	authCCRXName = "Hysteria-CC-RX"
)

// authEventHandler wraps the masquerade handler to report rejected /auth
// requests. sing-quic hands an /auth request to the masquerade handler only
// when the password matches no user, so the password is not checked again here.
// cover nil stands for sing-quic's default, a 404.
//
// The one exception: with a receive bandwidth set and ignore-client-bandwidth
// on, sing-quic also masquerades an authenticated client that asks for BBR
// (Hysteria-CC-RX 0). Such a request cannot be told apart from a wrong
// password here, so it is not reported, to keep own users out of the events.
func authEventHandler(cover http.Handler, receiveBPS uint64, ignoreClientBandwidth bool) http.Handler {
	if cover == nil {
		cover = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authevent.Enabled() && r.Method == http.MethodPost && r.Host == authHost && r.URL.Path == authPath {
			authPresent := r.Header.Get(authHeader) != ""
			rx, _ := strconv.ParseUint(r.Header.Get(authCCRXName), 10, 64)
			ambiguous := authPresent && receiveBPS > 0 && ignoreClientBandwidth && rx == 0
			if !ambiguous {
				reason := authevent.ReasonNoCredentials
				if authPresent {
					reason = authevent.ReasonWrongCredentials
				}
				local := ""
				if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && addr != nil {
					local = addr.String()
				}
				authevent.Emit(authevent.Event{Protocol: "hysteria2", Local: local, Remote: r.RemoteAddr, Reason: reason, Method: r.Method})
			}
		}
		cover.ServeHTTP(w, r)
	})
}
