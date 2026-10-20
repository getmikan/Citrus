// XDRIVE object names and session discovery follow XTLS/Xray-core at
// 92ccc939aaf4. SPDX-License-Identifier: MPL-2.0
package xdrive

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/log"
)

const (
	sessionsDir = "sessions"
	streamsDir  = "streams"
	maxSessions = 256
)

func sessionPrefix(id string) string  { return streamsDir + "/" + id }
func uplinkPrefix(id string) string   { return sessionPrefix(id) + "/c2s" }
func downlinkPrefix(id string) string { return sessionPrefix(id) + "/s2c" }
func announceName(id string, t time.Time) string {
	return fmt.Sprintf("%s/%d-%s", sessionsDir, t.UnixNano(), id)
}
func parseAnnounce(name string) (string, time.Time, bool) {
	stamp, id, ok := strings.Cut(name, "-")
	if !ok || len(id) != 32 {
		return "", time.Time{}, false
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", time.Time{}, false
	}
	n, err := strconv.ParseInt(stamp, 10, 64)
	return id, time.Unix(0, n), err == nil
}

type Client struct {
	ctx     context.Context
	cancel  context.CancelFunc
	storage Storage
	http    *http.Client
	params
	mu     sync.Mutex
	conns  map[*Conn]bool
	closed bool
}

func NewClient(c Config, h *http.Client) (*Client, error) {
	if h == nil {
		h = defaultHTTPClient(c)
	}
	storage, err := newStorage(c, h)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{ctx: ctx, cancel: cancel, storage: storage, http: h, params: paramsFromConfig(&c), conns: make(map[*Conn]bool)}, nil
}
func (c *Client) Dial(ctx context.Context) (net.Conn, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(random[:])
	announceCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	defer func() { stop(); cancel() }()
	if err := c.storage.Put(announceCtx, announceName(id, time.Now()), nil); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	var conn *Conn
	conn = newConn(c.ctx, c.storage, uplinkPrefix(id), downlinkPrefix(id), c.params, func() { c.mu.Lock(); delete(c.conns, conn); c.mu.Unlock() })
	c.conns[conn] = true
	return conn, nil
}
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	conns := make([]*Conn, 0, len(c.conns))
	for conn := range c.conns {
		conns = append(conns, conn)
	}
	c.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	c.http.CloseIdleConnections()
	return c.storage.Close()
}

type Listener struct {
	ctx     context.Context
	cancel  context.CancelFunc
	storage Storage
	http    *http.Client
	params
	accepted           chan net.Conn
	mu                 sync.Mutex
	active             map[string]*Conn
	handled, idleSince map[string]time.Time
	closeOnce          sync.Once
	closeErr           error
}

func Listen(c Config, h *http.Client) (*Listener, error) {
	if h == nil {
		h = defaultHTTPClient(c)
	}
	storage, err := newStorage(c, h)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &Listener{ctx: ctx, cancel: cancel, storage: storage, http: h, params: paramsFromConfig(&c), accepted: make(chan net.Conn, 32), active: make(map[string]*Conn), handled: make(map[string]time.Time), idleSince: make(map[string]time.Time)}
	go l.run()
	return l, nil
}
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	case conn := <-l.accepted:
		return conn, nil
	}
}
func (l *Listener) Addr() net.Addr { return placeholderAddr }
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		l.cancel()
		l.mu.Lock()
		conns := make([]*Conn, 0, len(l.active))
		for _, conn := range l.active {
			conns = append(conns, conn)
		}
		l.mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
		l.http.CloseIdleConnections()
		l.closeErr = l.storage.Close()
	})
	return l.closeErr
}
func (l *Listener) run() {
	delay := l.minPollInterval
	active := time.Now()
	collected := time.Now()
	for {
		accepted, err := l.acceptPending()
		if err != nil && l.ctx.Err() == nil {
			log.Warnln("[XDRIVE] session discovery: %v", err)
		}
		if accepted {
			active = time.Now()
		}
		if time.Since(active) < l.eagerWindow {
			delay = l.minPollInterval
		} else {
			delay = min(delay*2, l.maxPollInterval)
		}
		if time.Since(collected) >= l.sessionTTL/2 {
			_ = l.collect()
			collected = time.Now()
		}
		timer := time.NewTimer(delay)
		select {
		case <-l.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (l *Listener) acceptPending() (bool, error) {
	entries, err := l.storage.List(l.ctx, sessionsDir)
	if err != nil {
		return false, err
	}
	accepted := false
	for _, entry := range entries {
		id, at, ok := parseAnnounce(entry.Name)
		if !ok {
			continue
		}
		if time.Since(at) > l.sessionTTL {
			_ = l.storage.Delete(l.ctx, sessionsDir+"/"+entry.Name)
			continue
		}
		l.mu.Lock()
		if l.active[id] != nil || !l.handled[id].IsZero() || len(l.active) >= maxSessions {
			l.mu.Unlock()
			continue
		}
		conn := newConn(l.ctx, l.storage, downlinkPrefix(id), uplinkPrefix(id), l.params, func() { l.mu.Lock(); delete(l.active, id); l.mu.Unlock() })
		l.active[id] = conn
		l.handled[id] = time.Now()
		l.mu.Unlock()
		select {
		case l.accepted <- conn:
			accepted = true
			_ = l.storage.Delete(l.ctx, sessionsDir+"/"+entry.Name)
		case <-l.ctx.Done():
			_ = conn.Close()
			return accepted, l.ctx.Err()
		}
	}
	return accepted, nil
}
func (l *Listener) collect() error {
	entries, err := l.storage.List(l.ctx, streamsDir)
	if err != nil {
		return err
	}
	now := time.Now()
	var expired []string
	l.mu.Lock()
	present := make(map[string]bool, len(entries))
	for _, entry := range entries {
		id := entry.Name
		if len(id) != 32 {
			continue
		}
		if _, err := hex.DecodeString(id); err != nil {
			continue
		}
		present[id] = true
		if l.active[id] != nil {
			delete(l.idleSince, id)
			continue
		}
		if since, ok := l.idleSince[id]; !ok {
			l.idleSince[id] = now
		} else if now.Sub(since) >= l.sessionTTL {
			expired = append(expired, id)
			delete(l.idleSince, id)
		}
	}
	for id := range l.idleSince {
		if !present[id] {
			delete(l.idleSince, id)
		}
	}
	for id, at := range l.handled {
		if l.active[id] == nil && now.Sub(at) >= l.sessionTTL {
			delete(l.handled, id)
		}
	}
	l.mu.Unlock()
	for _, id := range expired {
		if err := l.storage.Delete(l.ctx, sessionPrefix(id)); err != nil {
			return err
		}
	}
	return nil
}
