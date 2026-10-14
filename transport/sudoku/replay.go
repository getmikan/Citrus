package sudoku

import (
	"sync"
	"time"
)

var handshakeReplayTTL = 60 * time.Second

// maxHandshakeReplayEntries bounds the process-wide replay cache. An entry is
// one accepted client hello, kept for handshakeReplayTTL, so the cap covers
// about 2200 handshakes per second before the oldest entries are dropped early.
// An entry costs roughly 150 bytes (map slot, queue slot, hex user hash), so
// the cache stays near 20 MiB at worst, whatever user hashes clients send.
var maxHandshakeReplayEntries = 1 << 17

type replayKey struct {
	user  string
	nonce [kipHelloNonceSize]byte
}

type replayEntry struct {
	key    replayKey
	expiry int64 // unix nanoseconds
}

// handshakeReplayProtector rejects a client hello whose (user hash, nonce) pair
// was accepted within handshakeReplayTTL. The user hash comes from the client,
// so it is only part of the key: there is no per-user state that a client could
// multiply by sending new hashes. Entries expire in insertion order, and once
// the cache is full the oldest one is dropped, trading replay detection for that
// hello (which the attacker still cannot complete without the client's
// ephemeral key) for bounded memory.
type handshakeReplayProtector struct {
	mu    sync.Mutex
	seen  map[replayKey]int64
	queue []replayEntry // insertion order; the TTL is fixed, so also expiry order
	head  int
}

func (p *handshakeReplayProtector) allow(userHash string, nonce [kipHelloNonceSize]byte, now time.Time) bool {
	if userHash == "" {
		userHash = "_"
	}
	ttl := handshakeReplayTTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	nowNano := now.UnixNano()
	key := replayKey{user: userHash, nonce: nonce}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = make(map[replayKey]int64)
	}

	p.dropLocked(func(e replayEntry) bool { return e.expiry <= nowNano })

	if exp, ok := p.seen[key]; ok && nowNano < exp {
		return false
	}

	limit := maxHandshakeReplayEntries
	if limit <= 0 {
		limit = 1
	}
	if p.lenLocked() >= limit {
		dropped := 0
		excess := p.lenLocked() - limit + 1
		p.dropLocked(func(replayEntry) bool {
			dropped++
			return dropped <= excess
		})
	}

	exp := nowNano + int64(ttl)
	p.seen[key] = exp
	p.queue = append(p.queue, replayEntry{key: key, expiry: exp})
	return true
}

func (p *handshakeReplayProtector) lenLocked() int {
	return len(p.queue) - p.head
}

// dropLocked removes entries from the front of the queue while drop returns
// true. p.mu must be held.
func (p *handshakeReplayProtector) dropLocked(drop func(replayEntry) bool) {
	for p.head < len(p.queue) {
		e := p.queue[p.head]
		if !drop(e) {
			break
		}
		// The key may have been accepted again after this entry expired; only
		// the newest entry owns the map slot.
		if exp, ok := p.seen[e.key]; ok && exp == e.expiry {
			delete(p.seen, e.key)
		}
		p.queue[p.head] = replayEntry{}
		p.head++
	}
	if p.head == len(p.queue) {
		p.queue = p.queue[:0]
		p.head = 0
	} else if p.head > 1024 && p.head > len(p.queue)/2 {
		n := copy(p.queue, p.queue[p.head:])
		for i := n; i < len(p.queue); i++ {
			p.queue[i] = replayEntry{}
		}
		p.queue = p.queue[:n]
		p.head = 0
	}
}

var globalHandshakeReplay = &handshakeReplayProtector{}
