// Command cmp is the server comparison harness: it generates the server and
// client configs, runs the sink (the destination of every proxied connection
// and the REALITY target), drives the load through a client (Xray or sing-box,
// the same one for every server of a protocol) and reads the server
// container's cgroup, and aggregates the results. See README.md.
package main

import (
	"fmt"
	"os"
)

// Addresses on the benchmark network (run.sh creates it). CMP_NET, the first
// three octets (default 10.77.0), moves them to another /24, so that two
// benchmark setups can share a Docker host.
var (
	serverIP = netPrefix() + ".10"
	sinkIP   = netPrefix() + ".20"
)

func netPrefix() string {
	if p := os.Getenv("CMP_NET"); p != "" {
		return p
	}
	return "10.77.0"
}

const (
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
	case "gate":
		err = cmdGate(os.Args[2:])
	default:
		printUsage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cmp:", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: cmp gen|sink|measure|report|gate [flags]")
	os.Exit(2)
}
