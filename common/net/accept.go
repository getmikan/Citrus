package net

import (
	"errors"
	"net"
	"time"
)

// AcceptBackoff paces an accept loop through failing Accept calls. Only a
// closed listener ends the loop: Temporary() misses resource exhaustion such as
// WSAEMFILE and WSAENOBUFS on Windows or ENOBUFS and ENOMEM on Linux, and
// treating those as fatal would leave the inbound dead until restart.
type AcceptBackoff struct {
	delay time.Duration
}

// Retry reports whether the loop should call Accept again after err. It waits
// with exponential back-off, 5ms doubling up to 1s as net/http does, and gives
// up when err means the listener is closed or done is closed meanwhile.
func (b *AcceptBackoff) Retry(err error, done <-chan struct{}) bool {
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	if b.delay == 0 {
		b.delay = 5 * time.Millisecond
	} else if b.delay *= 2; b.delay > time.Second {
		b.delay = time.Second
	}
	timer := time.NewTimer(b.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-done:
		return false
	}
}

// Reset restarts the back-off after a successful Accept.
func (b *AcceptBackoff) Reset() { b.delay = 0 }
