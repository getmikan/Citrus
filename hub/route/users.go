package route

import (
	"strconv"

	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// userFilter builds a filter from the `inbound` and `user` query parameters;
// an absent parameter matches everything.
func userFilter(r *http.Request) func(inbound, user string) bool {
	query := r.URL.Query()
	inbound, hasInbound := query.Get("inbound"), query.Has("inbound")
	user, hasUser := query.Get("user"), query.Has("user")
	return func(in, u string) bool {
		return (!hasInbound || in == inbound) && (!hasUser || u == user)
	}
}

// trafficUsers serves GET /traffic/users: the per-user counters, cumulative,
// or since the previous reset with ?reset=true (the reset happens in the same
// step, so no byte is reported twice or lost).
func trafficUsers(w http.ResponseWriter, r *http.Request) {
	reset := false
	if s := r.URL.Query().Get("reset"); s != "" {
		var err error
		if reset, err = strconv.ParseBool(s); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("reset: "+err.Error()))
			return
		}
	}
	match := userFilter(r)
	filter := func(key statistic.UserKey) bool { return match(key.Inbound, key.User) }
	users := statistic.DefaultManager.Users()
	var stats []statistic.UserStat
	if reset {
		stats = users.DrainFunc(filter)
	} else {
		stats = users.SnapshotFunc(filter)
	}
	render.JSON(w, r, stats)
}
