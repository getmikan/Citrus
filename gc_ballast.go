package main

import "os"

// gcBallastSize raises the garbage collector's heap goal without using memory.
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
const gcBallastSize = 8 << 20

var gcBallast []byte

func init() {
	if os.Getenv("GOGC") == "" && os.Getenv("GOMEMLIMIT") == "" {
		gcBallast = make([]byte, gcBallastSize)
	}
}
