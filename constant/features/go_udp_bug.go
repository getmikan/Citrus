package features

import "strings"

// AffectedByGoIssue78041 reports whether a Go toolchain version string (as
// returned by runtime.Version) has the Windows UDP stack corruption bug
// https://go.dev/issue/78041.
//
// In go1.26.0 and go1.26.1, internal/poll.(*FD).ReadFrom* on Windows passes
// the address of a stack variable as lpFromlen to an overlapped WSARecvFrom.
// When the receive completes asynchronously the kernel writes the sockaddr
// length (16 or 28) into a stack slot that by then belongs to another frame,
// typically the upper half of a return address, and the process dies with
// "fatal error: fault", "unexpected signal" or "index out of range" in an
// unrelated place. Every net.UDPConn.ReadFrom* is affected, which includes the
// Mieru UDP transport, the DNS server and UDP relays. Fixed in go1.26.2.
func AffectedByGoIssue78041(goVersion string) bool {
	// Custom toolchains may append a suffix, e.g. "go1.26.1 X:nocoverageredesign".
	goVersion, _, _ = strings.Cut(goVersion, " ")
	switch goVersion {
	case "go1.26.0", "go1.26.1", "go1.26rc1", "go1.26rc2", "go1.26rc3":
		return true
	}
	return false
}
