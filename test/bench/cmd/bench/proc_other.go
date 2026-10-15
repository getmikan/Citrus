//go:build !linux && !windows

package main

import "syscall"

// processRSS is unknown here; the Go runtime figures are still reported.
func processRSS() uint64 { return 0 }

func processCPU() (user, sys float64, ok bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, 0, false
	}
	tv := func(t syscall.Timeval) float64 { return float64(t.Sec) + float64(t.Usec)/1e6 }
	return tv(ru.Utime), tv(ru.Stime), true
}
