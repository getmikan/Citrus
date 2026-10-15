package metrics

import (
	"net/netip"
	"strconv"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// BenchmarkWritePerUser10k measures a scrape with 10k users, each with an open
// connection and some traffic.
func BenchmarkWritePerUser10k(b *testing.B) {
	um := statistic.DefaultManager.Users()
	in := "bench-" + utils.NewUUIDV4().String()
	ip := netip.MustParseAddr("192.0.2.40")
	for i := 0; i < 10000; i++ {
		key := statistic.UserKey{Inbound: in, User: "user-" + strconv.Itoa(i)}
		c := um.Acquire(key, ip)
		c.AddUp(int64(i) * 1000)
		c.AddDown(int64(i) * 10000)
		b.Cleanup(func() { um.Release(c, ip) })
	}
	o := Options{Enable: true, PerUser: true}
	var n countingWriter
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n = 0
		if err := Write(&n, o); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(n), "bytes/scrape")
}

type countingWriter int

func (c *countingWriter) Write(p []byte) (int, error) {
	*c += countingWriter(len(p))
	return len(p), nil
}
