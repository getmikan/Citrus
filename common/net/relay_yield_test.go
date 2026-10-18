package net

import (
	"io"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRelayYieldLimits(t *testing.T) {
	var y relayYield
	y.add(relayYieldBytes - 1)
	assert.Equal(t, relayYieldBytes-1, y.bytes)
	assert.True(t, y.since.IsZero(), "no clock before relayYieldBytes")
	y.add(1)
	assert.False(t, y.since.IsZero(), "the clock starts at relayYieldBytes")
	y.add(relayYieldBytes)
	assert.Equal(t, 2*relayYieldBytes, y.bytes, "no yield before relayYieldInterval")
	y.since = y.since.Add(-relayYieldInterval)
	y.add(1)
	assert.Equal(t, 0, y.bytes, "the count starts over after a yield")
}

// endlessReader always has data at once, like the source of a bulk download
// on a loaded server, until stop is set.
type endlessReader struct{ stop *atomic.Bool }

func (r endlessReader) Read(b []byte) (int, error) {
	if r.stop.Load() {
		return 0, io.EOF
	}
	return len(b), nil
}

// TestCopyConnYields runs a copy that never blocks on one processor next to
// a goroutine that wakes up every 100 µs. Without yields the copy keeps the
// processor for its whole time slice (10 ms) and the other goroutine runs
// about once per slice; with them it runs about every relayYieldInterval.
func TestCopyConnYields(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))

	var stop atomic.Bool
	var wakeups atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			time.Sleep(100 * time.Microsecond)
			wakeups.Add(1)
		}
	}()
	copied := make(chan error, 1)
	go func() {
		_, err := copyConn(onlyWriter{io.Discard}, endlessReader{&stop})
		copied <- err
	}()

	const window = 500 * time.Millisecond
	time.Sleep(window) // the copy runs; this goroutine is a timer too
	stop.Store(true)
	require.NoError(t, <-copied)
	<-done

	// About 50 without yields (one per time slice), about 500 with them.
	n := wakeups.Load()
	assert.Greater(t, n, int64(150), "the other goroutine ran %d times in %s", n, window)
}
