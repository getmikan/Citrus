package route

import (
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/log"
)

// UnixSocketModeEnv overrides the file mode of the external controller unix socket.
// The value is an octal permission mask, e.g. "0660" to also allow the owner's group.
const UnixSocketModeEnv = "CITRUS_UNIX_SOCKET_MODE"

// defaultUnixSocketMode only allows the user the core runs as to connect.
const defaultUnixSocketMode fs.FileMode = 0o600

// unixSocketMode returns the permissions for the external controller unix socket.
func unixSocketMode() fs.FileMode {
	value := strings.TrimSpace(os.Getenv(UnixSocketModeEnv))
	if value == "" {
		return defaultUnixSocketMode
	}
	mode, err := parseUnixSocketMode(value)
	if err != nil {
		log.Warnln("Invalid %s %q, using %#o: %s", UnixSocketModeEnv, value, defaultUnixSocketMode, err)
		return defaultUnixSocketMode
	}
	return mode
}

func parseUnixSocketMode(value string) (fs.FileMode, error) {
	value = strings.TrimPrefix(strings.TrimPrefix(value, "0o"), "0O")
	mode, err := strconv.ParseUint(value, 8, 32)
	if err != nil {
		return 0, err
	}
	if mode > 0o777 {
		return 0, strconv.ErrRange
	}
	return fs.FileMode(mode), nil
}
