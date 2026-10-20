// Package xdrive implements Xray-compatible remote-storage stream transport.
package xdrive

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Config struct {
	Fronting          string         `proxy:"fronting,omitempty" inbound:"fronting,omitempty" yaml:"fronting,omitempty" json:"fronting,omitempty"`
	RemoteFolder      string         `proxy:"remote-folder" inbound:"remote-folder" yaml:"remote-folder" json:"remote-folder"`
	Service           string         `proxy:"service" inbound:"service" yaml:"service" json:"service"`
	Secrets           []string       `proxy:"secrets,omitempty" inbound:"secrets,omitempty" yaml:"secrets,omitempty" json:"secrets,omitempty"`
	SegmentBytes      uint32         `proxy:"segment-bytes,omitempty" inbound:"segment-bytes,omitempty" yaml:"segment-bytes,omitempty" json:"segment-bytes,omitempty"`
	FlushIntervalMs   uint32         `proxy:"flush-interval-ms,omitempty" inbound:"flush-interval-ms,omitempty" yaml:"flush-interval-ms,omitempty" json:"flush-interval-ms,omitempty"`
	PollIntervalMs    uint32         `proxy:"poll-interval-ms,omitempty" inbound:"poll-interval-ms,omitempty" yaml:"poll-interval-ms,omitempty" json:"poll-interval-ms,omitempty"`
	MaxPollIntervalMs uint32         `proxy:"max-poll-interval-ms,omitempty" inbound:"max-poll-interval-ms,omitempty" yaml:"max-poll-interval-ms,omitempty" json:"max-poll-interval-ms,omitempty"`
	SessionTtlSeconds uint32         `proxy:"session-ttl-seconds,omitempty" inbound:"session-ttl-seconds,omitempty" yaml:"session-ttl-seconds,omitempty" json:"session-ttl-seconds,omitempty"`
	Concurrency       uint32         `proxy:"concurrency,omitempty" inbound:"concurrency,omitempty" yaml:"concurrency,omitempty" json:"concurrency,omitempty"`
	EagerWindowMs     uint32         `proxy:"eager-window-ms,omitempty" inbound:"eager-window-ms,omitempty" yaml:"eager-window-ms,omitempty" json:"eager-window-ms,omitempty"`
	HoleTimeoutMs     uint32         `proxy:"hole-timeout-ms,omitempty" inbound:"hole-timeout-ms,omitempty" yaml:"hole-timeout-ms,omitempty" json:"hole-timeout-ms,omitempty"`
	Template          map[string]any `proxy:"template,omitempty" inbound:"template,omitempty" yaml:"template,omitempty" json:"template,omitempty"`
}

func (c Config) Validate() error {
	if c.Fronting != "" {
		host, port, err := net.SplitHostPort(c.Fronting)
		p, portErr := strconv.ParseUint(port, 10, 16)
		if err != nil || host == "" || portErr != nil || p == 0 {
			return fmt.Errorf("xdrive fronting must be a host:port address")
		}
	}
	if c.RemoteFolder == "" {
		return fmt.Errorf("xdrive requires remote-folder")
	}
	switch c.Service {
	case "local":
	case "google-drive", "Google Drive":
		if len(c.Secrets) != 3 {
			return fmt.Errorf("xdrive google-drive needs client ID, client secret and refresh token")
		}
		for _, secret := range c.Secrets {
			if strings.TrimSpace(secret) == "" {
				return fmt.Errorf("xdrive google-drive secrets must not be empty")
			}
		}
	case "template":
		if len(c.Template) == 0 {
			return fmt.Errorf("xdrive template service requires a template object")
		}
	default:
		return fmt.Errorf("unsupported xdrive service %q", c.Service)
	}
	return nil
}

// Preserve upstream error wrapping without importing Xray's transport framework.
type storageError struct {
	message string
	cause   error
}

func newError(args ...any) *storageError             { return &storageError{message: fmt.Sprint(args...)} }
func (e *storageError) Base(err error) *storageError { e.cause = err; return e }
func (e *storageError) Error() string {
	if e.cause != nil {
		return e.message + ": " + e.cause.Error()
	}
	return e.message
}
func (e *storageError) Unwrap() error { return e.cause }
