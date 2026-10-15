package metrics

import (
	"os"
	"syscall"
)

// openFDs returns the number of open file descriptors and their limit.
func openFDs() (open, max int64, ok bool) {
	d, err := os.Open("/proc/self/fd")
	if err != nil {
		return 0, 0, false
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return 0, 0, false
	}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
		max = int64(lim.Cur)
	}
	// the descriptor of the directory itself is listed too
	return int64(len(names)) - 1, max, true
}
