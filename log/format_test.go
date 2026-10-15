package log

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestLogFormatUnmarshalText(t *testing.T) {
	for in, want := range map[string]LogFormat{"": TextFormat, "text": TextFormat, "TEXT": TextFormat, "json": JSONFormat, "Json": JSONFormat} {
		var f LogFormat
		require.NoError(t, f.UnmarshalText([]byte(in)), in)
		require.Equal(t, want, f, in)
	}

	var f LogFormat
	require.Error(t, f.UnmarshalText([]byte("custom-text")))
}

func captureLine(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	logrus.SetOutput(&buf)
	defer logrus.SetOutput(os.Stdout)
	defer SetLevel(Level())
	SetLevel(INFO)
	print(Event{LogLevel: WARNING, Payload: "a \"quoted\"\nline"})
	return buf.String()
}

func TestSetFormat(t *testing.T) {
	defer SetFormat(TextFormat, "")

	SetFormat(JSONFormat, "2006-01-02")
	f, layout := Format()
	require.Equal(t, JSONFormat, f)
	require.Equal(t, "2006-01-02", layout)

	line := captureLine(t)
	require.True(t, strings.HasSuffix(line, "}\n"), line)
	require.Equal(t, 1, strings.Count(line, "\n"), "one object per line")
	var obj map[string]string
	require.NoError(t, json.Unmarshal([]byte(line), &obj))
	require.Equal(t, "warning", obj["level"])
	require.Equal(t, "a \"quoted\"\nline", obj["msg"])
	require.Len(t, obj["time"], len("2006-01-02"))

	// empty layout falls back to the default one, text output as before
	SetFormat(TextFormat, "")
	f, layout = Format()
	require.Equal(t, TextFormat, f)
	require.Equal(t, DefaultTimestampFormat, layout)
	line = captureLine(t)
	require.Contains(t, line, "level=warning")
	require.Contains(t, line, `msg="a \"quoted\"\nline"`)
}
