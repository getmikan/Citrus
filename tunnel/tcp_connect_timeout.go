package tunnel

import (
	"context"
	"fmt"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	C "github.com/metacubex/mihomo/constant"
)

const (
	// MinTCPConnectTimeout is the smallest accepted tcp-connect-timeout in
	// milliseconds. A lower value cannot fit a proxy handshake and most likely
	// means the value was written in seconds instead of milliseconds.
	MinTCPConnectTimeout int64 = 100
	// MaxTCPConnectTimeout is the largest accepted tcp-connect-timeout in
	// milliseconds (10 minutes).
	MaxTCPConnectTimeout int64 = 10 * 60 * 1000
)

var tcpConnectTimeout = atomic.NewTypedValue(C.DefaultTCPTimeout)

// ValidateTCPConnectTimeout validates a connection budget in milliseconds.
func ValidateTCPConnectTimeout(milliseconds int64) error {
	if milliseconds < MinTCPConnectTimeout || milliseconds > MaxTCPConnectTimeout {
		return fmt.Errorf("tcp-connect-timeout must be between %d and %d milliseconds, got %d",
			MinTCPConnectTimeout, MaxTCPConnectTimeout, milliseconds)
	}
	return nil
}

// SetTCPConnectTimeout changes the budget for new tunnel TCP connections.
func SetTCPConnectTimeout(milliseconds int64) error {
	if err := ValidateTCPConnectTimeout(milliseconds); err != nil {
		return err
	}
	tcpConnectTimeout.Store(time.Duration(milliseconds) * time.Millisecond)
	return nil
}

func TCPConnectTimeout() time.Duration {
	return tcpConnectTimeout.Load()
}

func tcpConnectContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, TCPConnectTimeout())
}
