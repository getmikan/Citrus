package main

import (
	"syscall"
	"unsafe"
)

var procGetProcessMemoryInfo = syscall.NewLazyDLL("kernel32.dll").NewProc("K32GetProcessMemoryInfo")

type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// processRSS is the working set of the process.
func processRSS() uint64 {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0
	}
	var c processMemoryCounters
	c.CB = uint32(unsafe.Sizeof(c))
	r, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&c)), uintptr(c.CB))
	if r == 0 {
		return 0
	}
	return uint64(c.WorkingSetSize)
}

func processCPU() (user, sys float64, ok bool) {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, 0, false
	}
	var creation, exit, kernel, usr syscall.Filetime
	if err := syscall.GetProcessTimes(h, &creation, &exit, &kernel, &usr); err != nil {
		return 0, 0, false
	}
	ft := func(f syscall.Filetime) float64 {
		return float64(uint64(f.HighDateTime)<<32|uint64(f.LowDateTime)) * 100 / 1e9
	}
	return ft(usr), ft(kernel), true
}
