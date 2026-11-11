//go:build !linux

package outbound

import "net"

// desyncStopHopRecording has nothing to turn off: desync.ControlAutoTTL
// changes a socket only on Linux.
func desyncStopHopRecording(net.Conn) {}
