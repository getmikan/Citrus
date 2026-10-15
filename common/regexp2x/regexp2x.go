// Package regexp2x compiles user-supplied regexp2 patterns (rules, proxy
// filters) with a match timeout. regexp2 backtracks, so a pathological pattern
// against a long input can otherwise run for an unbounded time on the
// connection or reload path. A match that times out counts as no match.
package regexp2x

import (
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"

	"github.com/dlclark/regexp2"
)

// MatchTimeout bounds one match. Real patterns over domain or proxy names
// finish in microseconds.
const MatchTimeout = 100 * time.Millisecond

// Compile is regexp2.Compile with MatchTimeout set.
func Compile(expr string, opt regexp2.RegexOptions) (*regexp2.Regexp, error) {
	re, err := regexp2.Compile(expr, opt)
	if err != nil {
		return nil, err
	}
	re.MatchTimeout = MatchTimeout
	return re, nil
}

// MustCompile is regexp2.MustCompile with MatchTimeout set.
func MustCompile(expr string, opt regexp2.RegexOptions) *regexp2.Regexp {
	re := regexp2.MustCompile(expr, opt)
	re.MatchTimeout = MatchTimeout
	return re
}

// SetTimeout sets MatchTimeout on a pattern compiled elsewhere (e.g. decoded
// from configuration). It must be called before the pattern is in use.
func SetTimeout(re *regexp2.Regexp) {
	if re != nil {
		re.MatchTimeout = MatchTimeout
	}
}

var loggedTimeouts sync.Map // pattern string -> struct{}

// MatchString reports whether re matches s. An error (a match timeout) is no
// match; it is logged at debug level once per pattern.
func MatchString(re *regexp2.Regexp, s string) bool {
	matched, err := re.MatchString(s)
	if err != nil {
		if _, logged := loggedTimeouts.LoadOrStore(re.String(), struct{}{}); !logged {
			log.Debugln("[Regexp] %q: %v, treated as no match", re.String(), err)
		}
		return false
	}
	return matched
}
