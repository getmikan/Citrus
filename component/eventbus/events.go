package eventbus

// Payloads of the events (Event.Data).

// UserLimit is the data of a user.limit event.
type UserLimit struct {
	Inbound string `json:"inbound"`
	User    string `json:"user"`
	// Reason is "quota", "expired", "max-conns" or "max-ips".
	Reason string `json:"reason"`
	// Action is "closed" (the quota was used up or the user expired: its
	// connections are closed) or "rejected" (a new connection was refused).
	Action string `json:"action"`
	Detail string `json:"detail,omitempty"`
	// Remote is the client address of a rejected connection.
	Remote string `json:"remote,omitempty"`
	// Suppressed is the number of rejections of the user not reported since
	// the previous rejected event (a user is reported at most once a second).
	Suppressed int64 `json:"suppressed,omitempty"`
}

// Actions of a user.limit event.
const (
	LimitClosed   = "closed"
	LimitRejected = "rejected"
)

// UserChanged is the data of a user.changed event.
type UserChanged struct {
	Inbound string   `json:"inbound"`
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
	Changed []string `json:"changed,omitempty"`
}

// Status values of config.reload and provider.update.
const (
	StatusOK    = "ok"
	StatusError = "error"
)

// ConfigReload is the data of a config.reload event.
type ConfigReload struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// ProviderUpdate is the data of a provider.update event.
type ProviderUpdate struct {
	Name string `json:"name"`
	// Kind is "proxy" or "rule".
	Kind    string `json:"kind,omitempty"`
	Vehicle string `json:"vehicle,omitempty"`
	Status  string `json:"status"`
	// Changed is false when the content was the same as before.
	Changed bool   `json:"changed"`
	Error   string `json:"error,omitempty"`
}

// States of an inbound.state event.
const (
	InboundStarted = "started"
	InboundFailed  = "failed"
	InboundStopped = "stopped"
)

// InboundState is the data of an inbound.state event.
type InboundState struct {
	Inbound string `json:"inbound"`
	Type    string `json:"type,omitempty"`
	State   string `json:"state"`
	Error   string `json:"error,omitempty"`
}

// ChainHealth is the data of a chain.health event, sent when the health check
// of a chain group finds the chain in another state than the previous check.
type ChainHealth struct {
	Chain string `json:"chain"`
	Alive bool   `json:"alive"`
	// FailedHop is the first hop that failed (Position counts from 1); both
	// are empty when the chain is alive.
	FailedHop string `json:"failedHop,omitempty"`
	Position  int    `json:"position,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Dropped is the data of a dropped event.
type Dropped struct {
	Count uint64 `json:"count"`
}

// PublishConfigReload reports the result of a configuration reload.
func PublishConfigReload(err error) {
	if !Enabled(TypeConfigReload) {
		return
	}
	d := ConfigReload{Status: StatusOK}
	if err != nil {
		d = ConfigReload{Status: StatusError, Error: err.Error()}
	}
	Publish(TypeConfigReload, d)
}
