package sudoku

import (
	"fmt"
	"testing"
	"time"
)

func setReplayCacheLimit(t *testing.T, limit int) {
	t.Helper()
	old := maxHandshakeReplayEntries
	maxHandshakeReplayEntries = limit
	t.Cleanup(func() { maxHandshakeReplayEntries = old })
}

func replayCacheSize(p *handshakeReplayProtector) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.seen)
}

func TestHandshakeReplayRejectsRepeatedNonce(t *testing.T) {
	p := &handshakeReplayProtector{}
	now := time.Now()
	var nonce [kipHelloNonceSize]byte
	nonce[0] = 1

	if !p.allow("aa", nonce, now) {
		t.Fatal("first hello rejected")
	}
	if p.allow("aa", nonce, now.Add(time.Second)) {
		t.Fatal("replayed hello accepted")
	}
	if !p.allow("bb", nonce, now.Add(time.Second)) {
		t.Fatal("same nonce under another user hash rejected")
	}
	if !p.allow("aa", nonce, now.Add(handshakeReplayTTL+time.Second)) {
		t.Fatal("hello rejected after its replay window")
	}
	if p.allow("aa", nonce, now.Add(handshakeReplayTTL+2*time.Second)) {
		t.Fatal("re-accepted hello not tracked again")
	}
}

// A client that sends a fresh user hash with every hello must not grow the
// process-wide cache without bound.
func TestHandshakeReplayCacheBoundedAcrossUserHashes(t *testing.T) {
	setReplayCacheLimit(t, 64)
	p := &handshakeReplayProtector{}
	now := time.Now()
	for i := 0; i < 10000; i++ {
		var nonce [kipHelloNonceSize]byte
		nonce[0] = byte(i)
		nonce[1] = byte(i >> 8)
		if !p.allow(fmt.Sprintf("%016x", i), nonce, now) {
			t.Fatalf("fresh hello %d rejected", i)
		}
	}
	if n := replayCacheSize(p); n > 64 {
		t.Fatalf("replay cache holds %d entries, want at most 64", n)
	}
	p.mu.Lock()
	queued := len(p.queue) - p.head
	p.mu.Unlock()
	if queued > 64 {
		t.Fatalf("replay queue holds %d entries, want at most 64", queued)
	}

	// the newest hellos are still protected
	var nonce [kipHelloNonceSize]byte
	last := 9999
	nonce[0] = byte(last)
	nonce[1] = byte(last >> 8)
	if p.allow(fmt.Sprintf("%016x", last), nonce, now) {
		t.Fatal("recent hello replay accepted")
	}
}

func TestHandshakeReplayCacheExpiresIdleEntries(t *testing.T) {
	p := &handshakeReplayProtector{}
	now := time.Now()
	for i := 0; i < 100; i++ {
		var nonce [kipHelloNonceSize]byte
		nonce[0] = byte(i)
		p.allow(fmt.Sprintf("user-%d", i), nonce, now)
	}
	var nonce [kipHelloNonceSize]byte
	p.allow("later", nonce, now.Add(handshakeReplayTTL+time.Second))
	if n := replayCacheSize(p); n != 1 {
		t.Fatalf("replay cache holds %d entries after the window, want 1", n)
	}
}
