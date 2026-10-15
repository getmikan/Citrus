package trusttunnel

import (
	"net"

	"github.com/metacubex/mihomo/component/authevent"
	"github.com/metacubex/mihomo/listener/inbounduser"

	"github.com/metacubex/http"
)

// verifyRequest is verify that also reports a rejected request to authevent.
func (s *Service) verifyRequest(request *http.Request, authorization string) (entry *inbounduser.Entry, loaded bool) {
	entry, loaded = s.verify(authorization)
	if !loaded && authevent.Enabled() {
		reason := authevent.ReasonNoCredentials
		if authorization != "" {
			reason = authevent.ReasonWrongCredentials
		} else if s.fallbackProxy != nil {
			// With a fallback, a request without credentials is a visit to the
			// cover site; reporting it would make every visitor look like a
			// failed login to fail2ban-style consumers.
			return
		}
		authevent.Emit(authevent.Event{
			Protocol: "trusttunnel",
			Local:    s.requestLocalAddr(request),
			Remote:   request.RemoteAddr,
			Reason:   reason,
			Method:   request.Method,
		})
	}
	return
}

// requestLocalAddr is the address the request arrived on: the TCP listener's for
// HTTP/1.1 and HTTP/2, the UDP socket's for HTTP/3.
func (s *Service) requestLocalAddr(request *http.Request) string {
	if addr, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && addr != nil {
		return addr.String()
	}
	if s.tcpListener != nil {
		return s.tcpListener.Addr().String()
	}
	return ""
}
