package net

import (
	"runtime"
	"time"
)

// A relay loop yields its processor (runtime.Gosched) once it has moved
// relayYieldBytes and run for relayYieldInterval since its last yield.
//
// The loop of a bulk transfer through a loaded server never blocks: its
// source always has data and its destination takes it. The Go scheduler then
// lets it run for a whole time slice (10 ms) before it preempts it, and a
// goroutine that the network poller made runnable, such as the one of an
// interactive connection that just received a packet, waits behind every such
// loop in the run queue: with 8 downloads on 2 cores, about 40 ms on each
// hop through the server. With the yields it waits for a few turns of about
// relayYieldInterval instead. What is left is the runtime's own network poll
// interval while no processor is idle (10 ms).
//
// A yield also wakes an idle processor, which may take the goroutine over:
// a cost on a lone transfer with idle cores, so it stays rare (both limits),
// and a connection that moves little (interactive traffic) never yields.
const (
	relayYieldBytes    = 256 << 10
	relayYieldInterval = time.Millisecond
)

// relayYield tracks a relay loop since its last yield.
type relayYield struct {
	bytes int
	since time.Time
}

// add counts n more bytes and yields when both limits are reached.
func (y *relayYield) add(n int) {
	y.bytes += n
	if y.bytes < relayYieldBytes {
		return
	}
	now := time.Now()
	if y.since.IsZero() {
		y.since = now
		return
	}
	if now.Sub(y.since) < relayYieldInterval {
		return
	}
	y.bytes = 0
	runtime.Gosched()
	y.since = time.Now()
}
