package log

import (
	"errors"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

// DefaultTimestampFormat is the layout used when log-timestamp-format is empty
const DefaultTimestampFormat = "2006-01-02T15:04:05.000000000Z07:00"

// LogFormat selects how the lines printed to stdout look.
// It does not touch the events sent to the controller's /logs.
type LogFormat int

const (
	// TextFormat is logrus's key=value text, the long-standing output
	TextFormat LogFormat = iota
	// JSONFormat prints one JSON object per line, for Loki/ELK and the like
	JSONFormat
)

// UnmarshalText unserialize LogFormat
func (f *LogFormat) UnmarshalText(data []byte) error {
	switch strings.ToLower(string(data)) {
	case "", "text":
		*f = TextFormat
	case "json":
		*f = JSONFormat
	default:
		return errors.New("invalid log-format, expected text or json")
	}
	return nil
}

// MarshalText serialize LogFormat
func (f LogFormat) MarshalText() ([]byte, error) {
	return []byte(f.String()), nil
}

func (f LogFormat) String() string {
	switch f {
	case JSONFormat:
		return "json"
	default:
		return "text"
	}
}

var (
	formatMux       sync.Mutex
	format          = TextFormat
	timestampFormat = DefaultTimestampFormat
)

// Format returns the current output format and timestamp layout
func Format() (LogFormat, string) {
	formatMux.Lock()
	defer formatMux.Unlock()
	return format, timestampFormat
}

// SetFormat switches the stdout formatter; an empty layout means DefaultTimestampFormat
func SetFormat(newFormat LogFormat, newTimestampFormat string) {
	if newTimestampFormat == "" {
		newTimestampFormat = DefaultTimestampFormat
	}

	formatMux.Lock()
	defer formatMux.Unlock()
	if newFormat == format && newTimestampFormat == timestampFormat {
		return
	}
	format, timestampFormat = newFormat, newTimestampFormat
	log.SetFormatter(newFormatter(newFormat, newTimestampFormat))
}

func newFormatter(f LogFormat, timestampFormat string) log.Formatter {
	switch f {
	case JSONFormat:
		return &log.JSONFormatter{
			TimestampFormat: timestampFormat,
		}
	default:
		return &log.TextFormatter{
			FullTimestamp:             true,
			TimestampFormat:           timestampFormat,
			EnvironmentOverrideColors: true,
		}
	}
}
