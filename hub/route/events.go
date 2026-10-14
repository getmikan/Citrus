package route

import (
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/eventbus"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// eventsDroppedInterval is how often a stream reports the events dropped for
// it because it read too slowly.
var eventsDroppedInterval = 5 * time.Second

// eventsBuffer is the number of events a stream may lag behind before events
// are dropped for it.
var eventsBuffer = eventbus.DefaultBuffer

// getEvents serves GET /events: the core events as they happen, filtered by
// ?types=auth,user.limit (all types without it). Like /logs and /traffic it
// is a websocket when the request asks for an upgrade (one JSON event per
// text message), otherwise a chunked response of newline-delimited JSON, or
// Server-Sent Events with Accept: text/event-stream.
func getEvents(w http.ResponseWriter, r *http.Request) {
	mask, err := eventbus.ParseTypes(r.URL.Query().Get("types"))
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}

	sub := eventbus.Subscribe(mask, eventsBuffer)
	defer sub.Close()

	var write func(e eventbus.Event) error
	done := r.Context().Done()
	if r.Header.Get("Upgrade") == "websocket" {
		conn, _, err := wsUpgrade(r, w)
		if err != nil {
			return
		}
		defer untrackStream(conn)
		closed := make(chan struct{})
		go func() { // the client sends nothing we use; a read error is the end
			_, _ = io.Copy(io.Discard, conn)
			close(closed)
		}()
		done = closed
		write = func(e eventbus.Event) error {
			buf, err := json.Marshal(e)
			if err != nil {
				return err
			}
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			return wsWriteServerText(conn, buf)
		}
	} else {
		flusher, ok := w.(http.Flusher)
		if !ok {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError("streaming unsupported"))
			return
		}
		sse := strings.Contains(r.Header.Get("Accept"), "text/event-stream")
		if sse {
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			w.Header().Set("Content-Type", "application/x-ndjson")
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		write = func(e eventbus.Event) error {
			buf, err := json.Marshal(e)
			if err != nil {
				return err
			}
			if sse {
				buf = append(append([]byte("event: "+e.Type+"\ndata: "), buf...), '\n', '\n')
			} else {
				buf = append(buf, '\n')
			}
			if _, err = w.Write(buf); err != nil {
				return err
			}
			flusher.Flush()
			return nil
		}
	}

	tick := time.NewTicker(eventsDroppedInterval)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case e, ok := <-sub.C():
			if !ok {
				return
			}
			if write(e) != nil {
				return
			}
		case <-tick.C:
			if n := sub.TakeDropped(); n > 0 {
				e := eventbus.Event{Type: eventbus.TypeDropped, Time: time.Now(), Data: eventbus.Dropped{Count: n}}
				if write(e) != nil {
					return
				}
			}
		}
	}
}
