package constant

import "errors"

// ErrProviderSkip is wrapped by every ProviderSkipError.
var ErrProviderSkip = errors.New("skipped in provider")

// ProviderSkipError is returned for proxy entries that a provider skips with a
// warning instead of failing the whole document: options refused for
// subscription entries and entries without a required security policy. The
// same errors stay fatal for proxies written in the top-level config.
//
// Providers log the message as is, so it must be a constant and never carry a
// value taken from the proxy mapping.
type ProviderSkipError string

func (e ProviderSkipError) Error() string { return string(e) }

func (e ProviderSkipError) Unwrap() error { return ErrProviderSkip }
