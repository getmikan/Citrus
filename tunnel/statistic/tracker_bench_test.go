package statistic_test

import (
	"net"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

type discardConn struct{ net.Conn }

func (discardConn) Read(b []byte) (int, error)  { return len(b), nil }
func (discardConn) Write(b []byte) (int, error) { return len(b), nil }
func (discardConn) Close() error                { return nil }
func (discardConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (discardConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }

func benchmarkTracker(b *testing.B, user string) {
	tracker := statistic.NewTCPTracker(outbound.NewConn(discardConn{}, outbound.NewDirect()), statistic.DefaultManager,
		userMetadata("bench", user, "10.9.9.9"), nil, 0, 0, true)
	defer tracker.Close()
	payload := make([]byte, 1500)
	b.SetBytes(int64(2 * len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = tracker.Write(payload)
			_, _ = tracker.Read(payload)
		}
	})
}

// BenchmarkTrackerReadWrite measures a Write plus a Read of 1500 bytes through
// a tracker, without and with a user counter.
func BenchmarkTrackerReadWrite(b *testing.B) {
	b.Run("anonymous", func(b *testing.B) { benchmarkTracker(b, "") })
	b.Run("user", func(b *testing.B) { benchmarkTracker(b, "alice") })
	// a user with a quota and a speed limit too high to ever wait: the cost
	// of the limit bookkeeping
	b.Run("limited", func(b *testing.B) {
		um := statistic.DefaultManager.Users()
		l := statistic.UserLimit{Inbound: "bench", User: "limited", SpeedUp: 1 << 50, SpeedDown: 1 << 50, Quota: 1 << 60}
		if err := um.SetLimit(l); err != nil {
			b.Fatal(err)
		}
		defer um.DeleteLimit(l.Key())
		benchmarkTracker(b, "limited")
	})
}

// BenchmarkTrackerNew measures opening and closing a tracked connection.
func BenchmarkTrackerNew(b *testing.B) {
	for _, user := range []string{"", "alice"} {
		name := "anonymous"
		if user != "" {
			name = "user"
		}
		b.Run(name, func(b *testing.B) {
			metadata := userMetadata("bench-new", user, "10.9.9.8")
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tracker := statistic.NewTCPTracker(outbound.NewConn(discardConn{}, outbound.NewDirect()), statistic.DefaultManager,
					metadata, nil, 0, 0, true)
				_ = tracker.Close()
			}
		})
	}
}
