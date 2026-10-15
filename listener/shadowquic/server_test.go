package shadowquic

import "testing"

// The listener used to advertise ~2^32 concurrent streams per connection.
func TestServerStreamLimits(t *testing.T) {
	for name, limit := range map[string]int64{
		"bidi": ServerMaxIncomingStreams,
		"uni":  ServerMaxIncomingUniStreams,
	} {
		if limit < 1024 || limit > 4096 {
			t.Errorf("%s stream limit %d, want a bounded value in [1024, 4096]", name, limit)
		}
	}
}
