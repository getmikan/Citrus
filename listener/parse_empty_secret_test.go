package listener

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/log"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// warningLog collects the warnings logged during a test.
type warningLog struct {
	mu    sync.Mutex
	lines []string
}

func watchWarnings(t *testing.T) *warningLog {
	t.Helper()
	w := &warningLog{}
	sub := log.Subscribe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for event := range sub {
			if event.LogLevel == log.WARNING {
				w.mu.Lock()
				w.lines = append(w.lines, event.Payload)
				w.mu.Unlock()
			}
		}
	}()
	t.Cleanup(func() {
		log.UnSubscribe(sub)
		<-done
	})
	return w
}

// seen returns the first warning so far that contains every part.
func (w *warningLog) seen(parts ...string) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, line := range w.lines {
		found := true
		for _, part := range parts {
			found = found && strings.Contains(line, part)
		}
		if found {
			return line, true
		}
	}
	return "", false
}

// find is seen waiting a moment for the log, which is delivered
// asynchronously.
func (w *warningLog) find(parts ...string) (string, bool) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		if line, ok := w.seen(parts...); ok || time.Now().After(deadline) {
			return line, ok
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A user with an empty secret needs no secret to log in (a Hysteria2 client
// that sends no auth at all gets in as such a user). The users API refuses
// one; a configuration still loads, with a warning naming the listener and
// the user. "has-secret" sorts and comes first, so a wrong warning of it
// would be logged before the one awaited.
func TestParseListenerWarnsOfEmptySecrets(t *testing.T) {
	warnings := watchWarnings(t)
	users := []any{
		map[string]any{"username": "has-secret", "password": "secret"},
		map[string]any{"username": "no-secret", "password": ""},
	}
	for _, mapping := range []map[string]any{
		{"name": "trojan-secrets", "type": "trojan", "allow-insecure": true, "users": users},
		{"name": "socks-secrets", "type": "socks", "users": users},
		{"name": "hysteria2-secrets", "type": "hysteria2", "certificate": "cert.pem", "private-key": "key.pem", // read at Listen
			"users": map[string]any{"has-secret": "secret", "no-secret": ""}},
		{"name": "shadowquic-secrets", "type": "shadowquic", "jls-upstream": map[string]any{"addr": "example.com:443"}, "users": users},
	} {
		mapping["listen"], mapping["port"] = "127.0.0.1", 0
		name := mapping["name"].(string)
		_, err := ParseListener(mapping)
		require.NoError(t, err, "%s: the listener still loads", name)

		line, ok := warnings.find(name+":", `"no-secret"`)
		if assert.True(t, ok, "%s: the empty secret is not warned of", name) {
			assert.Contains(t, line, "empty secret")
		}
		_, ok = warnings.seen(name+":", `"has-secret"`)
		assert.False(t, ok, "%s: a user with a secret is warned of", name)
	}
}
