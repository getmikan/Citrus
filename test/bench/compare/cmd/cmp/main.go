// Command cmp is the server comparison harness: it generates the server and
// client configs, runs the sink (the destination of every proxied connection
// and the REALITY target), drives the load through an Xray client and reads
// the server container's cgroup, and aggregates the results. See README.md.
package main

import (
	"fmt"
	"os"
)

// Fixed addresses on the benchmark network (run.sh creates it).
const (
	serverIP   = "10.77.0.10"
	sinkIP     = "10.77.0.20"
	serverPort = 443
	sinkPort   = 9000 // plain TCP sink
	sinkTLS    = 9443 // the same sink inside TLS 1.3 (inner-TLS variant)
	targetPort = 8443 // REALITY target, TLS 1.3
	benchSNI   = "bench.test"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
	}
	var err error
	switch os.Args[1] {
	case "gen":
		err = cmdGen(os.Args[2:])
	case "sink":
		err = cmdSink(os.Args[2:])
	case "measure":
		err = cmdMeasure(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	default:
		printUsage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cmp:", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: cmp gen|sink|measure|report [flags]")
	os.Exit(2)
}
