package route

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

const (
	wsTicketLifetime        = 30 * time.Second
	maxWSTickets            = 1024
	maxWSTicketRequestBytes = 4096
	maxWSTicketOriginBytes  = 2048
	wsTicketBytes           = 32
)

type wsTicket struct {
	target, origin string
	expires        time.Time
}

// Each router generation owns its tickets. Recreating the controller (including
// secret rotation) creates empty stores; tickets never outlive their listener.
type controllerAuth struct {
	secret  string
	legacy  bool
	mu      sync.Mutex
	tickets map[[sha256.Size]byte]wsTicket
	now     func() time.Time
	ttl     time.Duration
	limit   int
}

func newControllerAuth(secret string, legacy bool) *controllerAuth {
	return &controllerAuth{secret: secret, legacy: legacy, tickets: make(map[[sha256.Size]byte]wsTicket), now: time.Now, ttl: wsTicketLifetime, limit: maxWSTickets}
}

// Standalone endpoints such as health probes accept the bearer header only.
func authentication(secret string) func(http.Handler) http.Handler {
	return newControllerAuth(secret, false).middleware
}

func websocketRequest(r *http.Request) bool {
	if r.Method != http.MethodGet || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, token := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return true
		}
	}
	return false
}

func websocketTarget(u *url.URL) (string, bool) {
	if u.IsAbs() || u.Host != "" || u.Opaque != "" || u.Fragment != "" || u.RawPath != "" {
		return "", false
	}
	path := u.Path
	if path == "/connections/" {
		path = "/connections"
	}
	switch path {
	case "/logs", "/events", "/traffic", "/traffic/users", "/memory", "/connections":
	default:
		return "", false
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || query.Has("token") || query.Has("ticket") {
		return "", false
	}
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return path, true
}

func (a *controllerAuth) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if header := r.Header.Get("Authorization"); header != "" {
			bearer, token, found := strings.Cut(header, " ")
			if found && bearer == "Bearer" && safeEqual(token, a.secret) {
				next.ServeHTTP(w, r)
				return
			}
		} else if websocketRequest(r) {
			query, err := url.ParseQuery(r.URL.RawQuery)
			if err == nil {
				values, hasTicket := query["ticket"]
				if hasTicket {
					query.Del("ticket")
					u := *r.URL
					u.RawQuery = query.Encode()
					if target, ok := websocketTarget(&u); ok && len(values) == 1 && a.consume(values[0], target, r.Header.Get("Origin")) {
						r.Header.Set("Upgrade", "websocket")
						next.ServeHTTP(w, r)
						return
					}
				} else if a.legacy {
					values := query["token"]
					query.Del("token")
					u := *r.URL
					u.RawQuery = query.Encode()
					if _, ok := websocketTarget(&u); ok && len(values) == 1 && safeEqual(values[0], a.secret) {
						r.Header.Set("Upgrade", "websocket")
						next.ServeHTTP(w, r)
						return
					}
				}
			}
		}
		render.Status(r, http.StatusUnauthorized)
		render.JSON(w, r, ErrUnauthorized)
	})
}

func (a *controllerAuth) consume(token, target, origin string) bool {
	if len(token) != base64.RawURLEncoding.EncodedLen(wsTicketBytes) {
		return false
	}
	key := sha256.Sum256([]byte(token))
	a.mu.Lock()
	defer a.mu.Unlock()
	ticket, ok := a.tickets[key]
	if !ok {
		return false
	}
	if !a.now().Before(ticket.expires) {
		delete(a.tickets, key)
		return false
	}
	if ticket.target != target || (ticket.origin != "" && ticket.origin != origin) {
		return false
	}
	delete(a.tickets, key)
	return true
}

func (a *controllerAuth) issueTicket(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if len(r.Header.Get("Origin")) > maxWSTicketOriginBytes {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	var request struct {
		Path string `json:"path"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxWSTicketRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	u, err := url.ParseRequestURI(request.Path)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	target, ok := websocketTarget(u)
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	var random [wsTicketBytes]byte
	if _, err := rand.Read(random[:]); err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError("could not issue WebSocket ticket"))
		return
	}
	token := base64.RawURLEncoding.EncodeToString(random[:])
	key := sha256.Sum256([]byte(token))
	a.mu.Lock()
	now := a.now()
	for key, ticket := range a.tickets {
		if !now.Before(ticket.expires) {
			delete(a.tickets, key)
		}
	}
	if len(a.tickets) >= a.limit {
		a.mu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(int(a.ttl/time.Second)))
		render.Status(r, http.StatusTooManyRequests)
		render.JSON(w, r, newError("too many outstanding WebSocket tickets"))
		return
	}
	a.tickets[key] = wsTicket{target: target, origin: r.Header.Get("Origin"), expires: now.Add(a.ttl)}
	a.mu.Unlock()
	render.Status(r, http.StatusCreated)
	render.JSON(w, r, render.M{"ticket": token, "expires_in": int(a.ttl / time.Second)})
}
