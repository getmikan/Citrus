package log

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A line below the level is skipped while nobody subscribes, and still
// delivered to a subscriber (the /logs API filters by its own level).
func TestEnabledFollowsSubscribers(t *testing.T) {
	defer SetLevel(Level())
	SetLevel(WARNING)

	require.False(t, Enabled(DEBUG))
	require.False(t, Enabled(INFO))
	require.True(t, Enabled(WARNING))
	require.True(t, Enabled(ERROR))

	sub := Subscribe()
	require.True(t, Enabled(DEBUG))

	Debugln("debug line %d", 1)
	select {
	case e := <-sub:
		require.Equal(t, DEBUG, e.LogLevel)
		require.Equal(t, "debug line 1", e.Payload)
	case <-time.After(5 * time.Second):
		t.Fatal("the subscriber did not get the debug line")
	}

	UnSubscribe(sub)
	UnSubscribe(sub) // twice: harmless
	require.False(t, Enabled(DEBUG))

	SetLevel(SILENT)
	require.False(t, Enabled(ERROR))
}

func BenchmarkSkippedLine(b *testing.B) {
	defer SetLevel(Level())
	SetLevel(WARNING)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Infoln("[%s] %s --> %s", "TCP", "192.0.2.1:40000", "example.com:443")
	}
}
