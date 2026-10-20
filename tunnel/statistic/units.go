package statistic

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Units of the user limits.
//
// Sizes (quota) are bytes. A plain number is bytes; the suffixes K, M, G, T
// (optionally followed by B: KB, MB...) are powers of 1000, and Ki, Mi, Gi, Ti
// (KiB, MiB...) are powers of 1024. "100G" is 100 000 000 000 bytes.
//
// Rates (speed-up, speed-down) are bytes per second and take the same form,
// optionally followed by "/s" or "ps": "10M", "10MB/s" and "10MBps" are all
// 10 000 000 bytes per second. A lowercase b means bits: "80Mbps" (or "80Mb")
// is 80 000 000 bits, that is 10 000 000 bytes, per second.

var unitRegexp = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*(?:([kKmMgGtT])(i)?)?(B|b)?(ps|/s)?$`)

func parseUnits(s string, rate bool) (int64, error) {
	s = strings.TrimSpace(s)
	m := unitRegexp.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid value %q", s)
	}
	if !rate && (m[4] == "b" || m[5] != "") {
		return 0, fmt.Errorf("invalid size %q: a size is in bytes (K, M, G, T, KiB...), not a rate", s)
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid value %q: %w", s, err)
	}
	base := 1000.0
	if m[3] != "" {
		base = 1024
	}
	switch strings.ToUpper(m[2]) {
	case "K":
		v *= base
	case "M":
		v *= base * base
	case "G":
		v *= base * base * base
	case "T":
		v *= base * base * base * base
	}
	if m[4] == "b" {
		v /= 8
	}
	if v > math.MaxInt64/2 {
		return 0, fmt.Errorf("value %q is too large", s)
	}
	return int64(v), nil
}

// ParseSize parses a size in bytes: a number, or a string such as "100G",
// "1.5GB" or "512MiB" (K, M, G, T are powers of 1000; Ki, Mi... of 1024).
func ParseSize(v any) (int64, error) { return parseUnitValue(v, false) }

// ParseRate parses a rate in bytes per second: a number, or a string such as
// "10M", "10MB/s", "10MBps" (bytes) or "80Mbps", "80Mb" (bits).
func ParseRate(v any) (int64, error) { return parseUnitValue(v, true) }

func parseUnitValue(v any, rate bool) (int64, error) {
	switch v := v.(type) {
	case nil:
		return 0, nil
	case string:
		if v == "" {
			return 0, nil
		}
		return parseUnits(v, rate)
	default:
		n, err := parseInt(v)
		if err != nil {
			return 0, err
		}
		return n, nil
	}
}

func parseInt(v any) (int64, error) {
	switch v := v.(type) {
	case nil:
		return 0, nil
	case int:
		return int64(v), nil
	case int64:
		return v, nil
	case int32:
		return int64(v), nil
	case uint:
		return int64(v), nil
	case uint64:
		if v > math.MaxInt64 {
			return 0, fmt.Errorf("value %d is too large", v)
		}
		return int64(v), nil
	case uint32:
		return int64(v), nil
	case float64:
		if v != math.Trunc(v) || math.Abs(v) > math.MaxInt64/2 {
			return 0, fmt.Errorf("invalid integer %v", v)
		}
		return int64(v), nil
	case string:
		if v == "" {
			return 0, nil
		}
		return strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	default:
		return 0, fmt.Errorf("invalid value %v (%T)", v, v)
	}
}

// parseTime parses expire-at: unix seconds, or an RFC 3339 time.
func parseTime(v any) (int64, error) {
	if t, ok := v.(time.Time); ok { // a YAML timestamp
		return t.Unix(), nil
	}
	if s, ok := v.(string); ok && strings.ContainsAny(s, "-:T") {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
		if err != nil {
			return 0, fmt.Errorf("invalid time %q: want unix seconds or RFC 3339", s)
		}
		return t.Unix(), nil
	}
	return parseInt(v)
}

// ParseUserLimit builds a limit from a map with the keys of the `user-limits`
// configuration section: inbound, user, speed-up, speed-down, speed-group,
// max-conns, max-ips, quota, expire-at. The keys are case and dash insensitive, so the
// JSON names of UserLimit (speedUp, maxConns...) are accepted too.
func ParseUserLimit(m map[string]any) (UserLimit, error) {
	var l UserLimit
	for key, v := range m {
		var err error
		switch strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", ""), "_", "")) {
		case "inbound":
			l.Inbound, err = parseString(v)
		case "user":
			l.User, err = parseString(v)
		case "speedup":
			l.SpeedUp, err = ParseRate(v)
		case "speeddown":
			l.SpeedDown, err = ParseRate(v)
		case "speedgroup":
			l.SpeedGroup, err = parseString(v)
		case "maxconns":
			l.MaxConns, err = parseInt(v)
		case "maxips":
			l.MaxIPs, err = parseInt(v)
		case "quota":
			l.Quota, err = ParseSize(v)
		case "expireat":
			l.ExpireAt, err = parseTime(v)
		default:
			err = fmt.Errorf("unknown key")
		}
		if err != nil {
			return UserLimit{}, fmt.Errorf("%s: %w", key, err)
		}
	}
	return l, l.Validate()
}

func parseString(v any) (string, error) {
	switch v := v.(type) {
	case string:
		return v, nil
	case nil:
		return "", nil
	default:
		return fmt.Sprint(v), nil
	}
}
