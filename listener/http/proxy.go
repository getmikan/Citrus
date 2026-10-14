package http

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

type bodyWrapper struct {
	io.ReadCloser
	once     sync.Once
	onHitEOF func()
}

func (b *bodyWrapper) Read(p []byte) (n int, err error) {
	n, err = b.ReadCloser.Read(p)
	if err == io.EOF && b.onHitEOF != nil {
		b.once.Do(b.onHitEOF)
	}
	return n, err
}

type boundKey struct {
	user   string
	authed bool
}

func HandleConn(c net.Conn, tunnel C.Tunnel, store auth.AuthStore, additions ...inbound.Addition) {
	additions = append(additions, inbound.Placeholder) // Add a placeholder for InUser
	inUserIdx := len(additions) - 1
	client := newClient(c, tunnel, additions)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peekMutex := sync.Mutex{}

	// the request header is read through a byte limit, lifted for the body,
	// a CONNECT tunnel or an upgraded connection
	limited := &headerLimitConn{Conn: c}
	conn := N.NewBufferedConn(limited)

	lastUser := ""
	var bound map[boundKey]struct{} // what this connection is bound to

	for {
		peekMutex.Lock()
		// a request header must arrive in time; the deadline is lifted before
		// the body, a CONNECT tunnel or an upgraded connection is relayed
		authStore.SetHandshakeDeadline(c)
		limited.limit(MaxHeaderBytes)
		request, err := ReadRequest(conn.Reader())
		tooLarge := limited.unlimit()
		authStore.ClearHandshakeDeadline(c)
		peekMutex.Unlock()
		if err != nil {
			if tooLarge {
				_, _ = io.WriteString(conn, "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n")
			}
			break
		}

		request.RemoteAddr = conn.RemoteAddr().String()

		keepAlive := strings.TrimSpace(strings.ToLower(request.Header.Get("Proxy-Connection"))) == "keep-alive"

		// Every request is authenticated on its own, against the users of
		// the moment: a keep-alive connection carries no trust over from an
		// earlier request, and a request that fails is answered, never
		// forwarded.
		authenticator := store.Authenticator()
		resp, user := authenticate(request, authenticator)
		if resp == nil {
			// the connection dies with the user when its users can change
			// at runtime, and with the state "authentication off" when it is
			// turned on
			key := boundKey{user: user, authed: authenticator != nil}
			if _, ok := bound[key]; !ok {
				release, ok := authStore.BindSession(store, authenticator, user, c)
				if !ok {
					break // close connection
				}
				defer release()
				if bound == nil {
					bound = make(map[boundKey]struct{})
				}
				bound[key] = struct{}{}
			}
			additions[inUserIdx] = inbound.WithInUser(user)

			if request.Method == http.MethodConnect {
				// Manual writing to support CONNECT for http 1.0 (workaround for uplay client)
				if _, err = fmt.Fprintf(conn, "HTTP/%d.%d %03d %s\r\n\r\n", request.ProtoMajor, request.ProtoMinor, http.StatusOK, "Connection established"); err != nil {
					break // close connection
				}

				tunnel.HandleTCPConn(inbound.NewHTTPS(request, conn, additions...))

				return // hijack connection
			}

			host := request.Header.Get("Host")
			if host != "" {
				request.Host = host
			}

			request.RequestURI = ""

			if isUpgradeRequest(request) {
				handleUpgrade(conn, request, tunnel, additions...)

				return // hijack connection
			}

			// ensure there is a client with correct additions
			// when the authenticated user changed, outbound client should close idle connections
			if user != lastUser {
				client.CloseIdleConnections()
				lastUser = user
			}

			removeHopByHopHeaders(request.Header)
			removeExtraHTTPHostPort(request)

			if request.URL.Scheme == "" || request.URL.Host == "" {
				resp = responseWith(request, http.StatusBadRequest)
			} else {
				request = request.WithContext(ctx)

				startBackgroundRead := func() {
					go func() {
						peekMutex.Lock()
						defer peekMutex.Unlock()
						_, err := conn.Peek(1)
						if err != nil {
							cancel()
						}
					}()
				}
				if request.Body == nil || request.Body == http.NoBody {
					startBackgroundRead()
				} else {
					request.Body = &bodyWrapper{ReadCloser: request.Body, onHitEOF: startBackgroundRead}
				}
				resp, err = client.Do(request)
				if err != nil {
					resp = responseWith(request, http.StatusBadGateway)
				}
			}

			removeHopByHopHeaders(resp.Header)
		} else if resp.StatusCode != http.StatusProxyAuthRequired ||
			(request.Body != nil && request.Body != http.NoBody) {
			// Wrong credentials get no second try on this connection. A
			// request without credentials may be retried with them (browsers
			// do), unless its unread body is still in the way.
			keepAlive = false
		}

		if !keepAlive {
			resp.Close = true // close connection if keep-alive is not set
		}
		if keepAlive && resp.ContentLength > 0 {
			resp.Close = false // don't need to close connection if content length is positive numbers
		}

		if !resp.Close {
			resp.Header.Set("Proxy-Connection", "keep-alive")
			resp.Header.Set("Connection", "keep-alive")
			resp.Header.Set("Keep-Alive", "timeout=4")
		}

		err = resp.Write(conn)
		if err != nil || resp.Close {
			break // close connection
		}
	}

	_ = conn.Close()
}

// authenticate checks the credentials of one request. resp is nil when the
// request may be forwarded, and user is then the verified user. Without an
// authenticator every request passes with no user: a Proxy-Authorization
// header nobody verified does not name the user.
func authenticate(request *http.Request, authenticator auth.Authenticator) (resp *http.Response, user string) {
	if authenticator == nil {
		return nil, ""
	}
	credential := parseBasicProxyAuthorization(request)
	if credential == "" {
		resp = responseWith(request, http.StatusProxyAuthRequired)
		resp.Header.Set("Proxy-Authenticate", "Basic")
		return resp, ""
	}
	user, pass, err := decodeBasicProxyAuthorization(credential)
	if err != nil || !authenticator.Verify(user, pass) {
		log.Infoln("Auth failed from %s", request.RemoteAddr)
		return responseWith(request, http.StatusForbidden), ""
	}
	log.Debugln("Auth success from %s -> %s", request.RemoteAddr, user)
	return nil, user
}

func responseWith(request *http.Request, statusCode int) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Proto:      request.Proto,
		ProtoMajor: request.ProtoMajor,
		ProtoMinor: request.ProtoMinor,
		Header:     http.Header{},
	}
}
