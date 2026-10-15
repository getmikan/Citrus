package hysteria2_realm

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/httputils"
)

const (
	sessionTTL              = time.Minute
	reaperInterval          = time.Second
	defaultRealmNamePattern = `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`
)

const (
	eventsBufferSize   = 16
	maxPendingAttempts = eventsBufferSize
)

type session struct {
	id        string // the bearer token of the session: never logged
	logID     string // names the session in the logs, see sessionLogID
	realmID   string
	addresses []string
	expires   time.Time
	events    chan sessionEvent
	done      chan struct{}
	closed    bool
	clientIP  string
	pending   map[string]chan punchResponsePayload
	stream    chan struct{} // closed to end the current events stream
}

type sessionEvent struct {
	kind string
	data any
}

type punchResponsePayload struct {
	addresses []string
}

type serverConfig struct {
	realmToken     string
	maxRealms      int
	maxRealmsPerIP int
	realIP         httputils.RealIP
	realmIDPattern *regexp.Regexp
}

type server struct {
	mu             sync.Mutex
	realms         map[string]*session // realmID -> session
	sessions       map[string]*session // sessionID -> session
	ipCounts       map[string]int      // clientIP -> realm count
	realmToken     string
	maxRealms      int
	maxRealmsPerIP int
	realIP         httputils.RealIP
	realmIDPattern *regexp.Regexp
}

func newServer(cfg serverConfig) *server {
	pat := cfg.realmIDPattern
	if pat == nil {
		pat = regexp.MustCompile(defaultRealmNamePattern)
	}
	return &server{
		realms:         make(map[string]*session),
		sessions:       make(map[string]*session),
		ipCounts:       make(map[string]int),
		realmToken:     cfg.realmToken,
		maxRealms:      cfg.maxRealms,
		maxRealmsPerIP: cfg.maxRealmsPerIP,
		realIP:         cfg.realIP,
		realmIDPattern: pat,
	}
}

func randToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// sessionLogID names a session in the logs. The session ID is the bearer
// token of the heartbeat, events and connect-response calls, and the debug
// log reaches every log subscriber (the /logs stream, log files), so the logs
// carry a short digest of it instead: it tells the sessions apart and
// cannot be presented as the token.
func sessionLogID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:6])
}

func (s *server) getSessionByToken(token string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[token]
	if sess == nil || sess.closed || time.Now().After(sess.expires) {
		return nil
	}
	return sess
}

func (s *server) removeSession(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeSessionLocked(sess)
}

func (s *server) removeSessionLocked(sess *session) {
	if sess.closed {
		return
	}
	sess.closed = true
	close(sess.done)
	if s.realms[sess.realmID] == sess {
		delete(s.realms, sess.realmID)
	}
	if _, ok := s.sessions[sess.id]; ok {
		s.ipCounts[sess.clientIP]--
		if s.ipCounts[sess.clientIP] <= 0 {
			delete(s.ipCounts, sess.clientIP)
		}
	}
	delete(s.sessions, sess.id)
	for nonce, ch := range sess.pending {
		close(ch)
		delete(sess.pending, nonce)
	}
}

func (s *server) removeExpiredSession(sess *session, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.closed || !now.After(sess.expires) {
		return false
	}
	s.removeSessionLocked(sess)
	return true
}

func (s *server) registerPending(sess *session, nonce string) (chan punchResponsePayload, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.closed || len(sess.pending) >= maxPendingAttempts {
		return nil, false
	}
	if _, exists := sess.pending[nonce]; exists {
		// Nonce collision? Silently drop the attempt.
		return nil, false
	}
	ch := make(chan punchResponsePayload, 1)
	sess.pending[nonce] = ch
	return ch, true
}

func (s *server) deliverPending(sess *session, nonce string, payload punchResponsePayload) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.closed {
		return false
	}
	ch, ok := sess.pending[nonce]
	if !ok {
		return false
	}
	delete(sess.pending, nonce)
	select {
	case ch <- payload:
	default:
	}
	return true
}

func (s *server) cancelPending(sess *session, nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(sess.pending, nonce)
}

func (s *server) sendEvent(sess *session, ev sessionEvent) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.closed {
		return false
	}
	select {
	case sess.events <- ev:
		return true
	default:
		return false
	}
}

// acquireStream makes the caller the only events stream of the session:
// the stream it holds is closed, so a reconnecting client takes over from
// a stale stream instead of being locked out. It returns the channel that
// is closed when this stream is replaced, and false on a closed session.
func (s *server) acquireStream(sess *session) (chan struct{}, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.closed {
		return nil, false
	}
	if sess.stream != nil {
		close(sess.stream)
	}
	ch := make(chan struct{})
	sess.stream = ch
	return ch, true
}

// releaseStream drops the stream, unless a newer one has replaced it.
func (s *server) releaseStream(sess *session, ch chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.stream == ch {
		sess.stream = nil
	}
}

func (s *server) reaper(ctx context.Context) {
	t := time.NewTicker(reaperInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			now := time.Now()
			var expired []*session
			for _, sess := range s.sessions {
				if now.After(sess.expires) {
					expired = append(expired, sess)
				}
			}
			s.mu.Unlock()
			for _, sess := range expired {
				if s.removeExpiredSession(sess, now) {
					debugf("session expired realm=%s session=%s", sess.realmID, sess.logID)
				}
			}
		}
	}

}
