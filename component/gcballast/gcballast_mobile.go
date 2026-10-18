//go:build android || ios

package gcballast

// Active reports whether the ballast was allocated: never on android and
// ios, where memory matters more than the rate of new connections.
func Active() bool { return false }
