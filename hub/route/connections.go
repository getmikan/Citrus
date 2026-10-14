package route

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// The bounds of the interval (milliseconds) of the /connections websocket.
const (
	minConnectionsInterval = 1
	maxConnectionsInterval = 3600 * 1000
)

func connectionRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getConnections)
	r.Delete("/", closeAllConnections)
	r.Delete("/{id}", closeConnection)
	return r
}

func getConnections(w http.ResponseWriter, r *http.Request) {
	if !(r.Header.Get("Upgrade") == "websocket") {
		snapshot := statistic.DefaultManager.Snapshot()
		render.JSON(w, r, snapshot)
		return
	}

	// The interval is checked before the upgrade: after it the response
	// writer is gone, and a nonpositive ticker period panics.
	interval := 1000
	if intervalStr := r.URL.Query().Get("interval"); intervalStr != "" {
		t, err := strconv.Atoi(intervalStr)
		if err != nil || t < minConnectionsInterval || t > maxConnectionsInterval {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(fmt.Sprintf("interval must be %d to %d milliseconds", minConnectionsInterval, maxConnectionsInterval)))
			return
		}
		interval = t
	}

	conn, _, err := wsUpgrade(r, w)
	if err != nil {
		return
	}
	defer untrackStream(conn)

	buf := &bytes.Buffer{}
	sendSnapshot := func() error {
		buf.Reset()
		snapshot := statistic.DefaultManager.Snapshot()
		if err := json.NewEncoder(buf).Encode(snapshot); err != nil {
			return err
		}

		return wsWriteServerText(conn, buf.Bytes())
	}

	if err := sendSnapshot(); err != nil {
		return
	}

	tick := time.NewTicker(time.Millisecond * time.Duration(interval))
	defer tick.Stop()
	for range tick.C {
		if err := sendSnapshot(); err != nil {
			break
		}
	}
}

func closeConnection(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if c := statistic.DefaultManager.Get(id); c != nil {
		_ = c.Close()
	}
	render.NoContent(w, r)
}

// closeAllConnections closes all connections, or with the `inbound` and/or
// `user` query parameters only the connections of that inbound and user.
func closeAllConnections(w http.ResponseWriter, r *http.Request) {
	match := userFilter(r)
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		var inbound, user string
		if m := c.Info().Metadata; m != nil {
			inbound, user = m.InName, m.InUser
		}
		if match(inbound, user) {
			_ = c.Close()
		}
		return true
	})
	render.NoContent(w, r)
}
