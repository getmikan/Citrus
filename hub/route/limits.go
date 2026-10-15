package route

import (
	"encoding/json"
	"io"

	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// limitsRouter serves the per-user limits:
//
//	GET    /limits/users?inbound=&user=   the limits and their state
//	PUT    /limits/users?inbound=&user=   set the limit of a user ("*": default)
//	DELETE /limits/users?inbound=&user=   remove it
//	POST   /limits/users/reset-quota?inbound=&user=   reset the quota usage
func limitsRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/users", getUserLimits)
	r.Put("/users", putUserLimit)
	r.Delete("/users", deleteUserLimit)
	r.Post("/users/reset-quota", resetUserQuota)
	return r
}

func getUserLimits(w http.ResponseWriter, r *http.Request) {
	match := userFilter(r)
	render.JSON(w, r, statistic.DefaultManager.Users().LimitsFunc(func(key statistic.UserKey) bool {
		return match(key.Inbound, key.User)
	}))
}

// limitKey reads the inbound and the user of a PUT or DELETE from the query.
func limitKey(w http.ResponseWriter, r *http.Request) (statistic.UserKey, bool) {
	query := r.URL.Query()
	key := statistic.UserKey{Inbound: query.Get("inbound"), User: query.Get("user")}
	if key.Inbound == "" || key.User == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(`the "inbound" and "user" query parameters are required ("*" as user for the default of the inbound)`))
		return key, false
	}
	return key, true
}

// putUserLimit sets the limit of a user from a JSON object with the keys of
// the `user-limits` section (speed-up, speed-down, max-conns, max-ips, quota,
// expire-at; the camelCase names are accepted too) and the same units. A key
// left out is no limit. The quota usage of the user is kept.
func putUserLimit(w http.ResponseWriter, r *http.Request) {
	key, ok := limitKey(w, r)
	if !ok {
		return
	}
	body := map[string]any{}
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.UseNumber()
	if err := dec.Decode(&body); err != nil && err != io.EOF {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	for k, v := range body {
		if n, isNumber := v.(json.Number); isNumber {
			body[k] = n.String()
		}
	}
	for _, field := range []struct{ name, value string }{{"inbound", key.Inbound}, {"user", key.User}} {
		if v, set := body[field.name]; set && v != field.value {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(field.name+" in the body differs from the query"))
			return
		}
		body[field.name] = field.value
	}
	limit, err := statistic.ParseUserLimit(body)
	if err == nil {
		err = statistic.DefaultManager.Users().SetLimit(limit)
	}
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	status, _ := statistic.DefaultManager.Users().GetLimit(key)
	render.JSON(w, r, status)
}

func deleteUserLimit(w http.ResponseWriter, r *http.Request) {
	key, ok := limitKey(w, r)
	if !ok {
		return
	}
	if !statistic.DefaultManager.Users().DeleteLimit(key) {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
		return
	}
	render.NoContent(w, r)
}

// resetUserQuota sets the quota usage of the matching users (all without
// parameters) back to zero; the users over their quota are admitted again.
func resetUserQuota(w http.ResponseWriter, r *http.Request) {
	match := userFilter(r)
	n := statistic.DefaultManager.Users().ResetQuota(func(key statistic.UserKey) bool {
		return match(key.Inbound, key.User)
	})
	render.JSON(w, r, render.M{"reset": n})
}
