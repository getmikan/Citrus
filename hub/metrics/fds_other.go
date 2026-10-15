//go:build !linux

package metrics

// openFDs is only implemented on Linux (/proc/self/fd).
func openFDs() (open, max int64, ok bool) { return 0, 0, false }
