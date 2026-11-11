//go:build !linux || android

package gcballast

// Active reports whether the ballast was allocated: never outside Linux
// servers. Android and iOS care more about memory than about the rate of new
// connections, and Windows and macOS builds are desktop clients.
func Active() bool { return false }
