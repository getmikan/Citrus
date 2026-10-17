//go:build !android && !ios

// Package gcballast raises the garbage collector's heap goal of a server
// build. Importing it is enough.
package gcballast

import (
	"os"

	"github.com/metacubex/mihomo/constant/features"
)

// gcBallastSize is the size of the ballast, which raises the heap goal
// without using memory.
//
// The GC starts a cycle when the heap has grown by GOGC% of the live heap
// plus the globals. Citrus keeps both small: about 3 MB live and almost no
// globals on a server, against about 6 MB live and 5 MB of globals in
// upstream mihomo. Under a stream of new connections, each of which allocates
// tens of kilobytes that die with it, that small goal meant a GC cycle every
// few milliseconds, three times as many as upstream, and the collector took
// several percent of the CPU per connection (test/bench/compare, handshake
// phase: a heap goal of 6-8 MB against upstream's 17-20 MB).
//
// The ballast is one pointer-free allocation that is kept and never written:
// the GC counts it as live, so the goal grows by its size, but never scans it,
// and its pages are never touched, so it takes no RSS. What it costs is up to
// its size of extra garbage between two cycles under load. It is counted in
// the heap metrics and against GOMEMLIMIT, so it is left out when GOGC or
// GOMEMLIMIT is set: whoever tunes the GC gets exactly what they set.
//
// It is for servers only: android and ios builds (this file's build tags)
// and the embedded Android app (features.CMFA) go without it. On a phone the
// memory matters more and the rate of new connections is low.
const gcBallastSize = 8 << 20

var gcBallast []byte

func init() {
	if gcBallastWanted(os.Getenv) {
		gcBallast = make([]byte, gcBallastSize)
	}
}

// Active reports whether the ballast was allocated.
func Active() bool { return gcBallast != nil }

func gcBallastWanted(getenv func(string) string) bool {
	return !features.CMFA && getenv("GOGC") == "" && getenv("GOMEMLIMIT") == ""
}
