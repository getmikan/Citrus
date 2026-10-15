package route

import (
	"errors"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// Runtime user management of the `listeners:` inbounds:
//
//	GET    /inbounds/{name}/users         the users, names (and flows) only
//	PUT    /inbounds/{name}/users         replace all: {"users": [{"name", "secret", "flow"}]}
//	POST   /inbounds/{name}/users         add one: {"name", "secret", "flow"}
//	PATCH  /inbounds/{name}/users/{user}  change the secret and/or flow: {"secret", "flow"}
//	DELETE /inbounds/{name}/users/{user}  remove the user and close its connections
//
// 404: no such inbound (or user), 400: invalid users, 409: the inbound cannot
// change its users at runtime. The changes live in memory; a configuration
// reload sets the users of the configuration again.
func inboundRouter() http.Handler {
	r := chi.NewRouter()
	r.Route("/{name}/users", func(r chi.Router) {
		r.Get("/", getInboundUsers)
		r.Put("/", putInboundUsers)
		r.Post("/", postInboundUser)
		r.Patch("/{user}", patchInboundUser)
		r.Delete("/{user}", deleteInboundUser)
	})
	return r
}

// inboundUserInfo is a user as GET lists it: never with the secret.
type inboundUserInfo struct {
	Name string `json:"name"`
	Flow string `json:"flow,omitempty"`
}

type inboundUsersResponse struct {
	Inbound string            `json:"inbound"`
	Type    string            `json:"type"`
	Users   []inboundUserInfo `json:"users"`
}

func getInboundUsers(w http.ResponseWriter, r *http.Request) {
	name := getEscapeParam(r, "name")
	users, err := listener.InboundUsers(name)
	if err != nil {
		renderInboundError(w, r, name, err)
		return
	}
	resp := inboundUsersResponse{Inbound: name, Type: listener.InboundType(name), Users: make([]inboundUserInfo, len(users))}
	for i, user := range users {
		resp.Users[i] = inboundUserInfo{Name: user.Name, Flow: user.Flow}
	}
	render.JSON(w, r, resp)
}

func putInboundUsers(w http.ResponseWriter, r *http.Request) {
	name := getEscapeParam(r, "name")
	var req struct {
		Users *[]C.InboundUser `json:"users"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil || req.Users == nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if err := listener.SetInboundUsers(name, *req.Users); err != nil {
		renderInboundError(w, r, name, err)
		return
	}
	render.NoContent(w, r)
}

func postInboundUser(w http.ResponseWriter, r *http.Request) {
	name := getEscapeParam(r, "name")
	var user C.InboundUser
	if err := render.DecodeJSON(r.Body, &user); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if err := listener.AddInboundUser(name, user); err != nil {
		renderInboundError(w, r, name, err)
		return
	}
	render.Status(r, http.StatusCreated)
	render.JSON(w, r, inboundUserInfo{Name: user.Name, Flow: user.Flow})
}

func patchInboundUser(w http.ResponseWriter, r *http.Request) {
	name, user := getEscapeParam(r, "name"), getEscapeParam(r, "user")
	var req struct {
		Secret *string `json:"secret"`
		Flow   *string `json:"flow"`
	}
	if err := render.DecodeJSON(r.Body, &req); err != nil || (req.Secret == nil && req.Flow == nil) {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	err := listener.ModifyInboundUser(name, user, func(u *C.InboundUser) error {
		if req.Secret != nil {
			u.Secret = *req.Secret
		}
		if req.Flow != nil {
			u.Flow = *req.Flow
		}
		return nil
	})
	if err != nil {
		renderInboundError(w, r, name, err)
		return
	}
	render.NoContent(w, r)
}

func deleteInboundUser(w http.ResponseWriter, r *http.Request) {
	name, user := getEscapeParam(r, "name"), getEscapeParam(r, "user")
	if err := listener.RemoveInboundUser(name, user); err != nil {
		renderInboundError(w, r, name, err)
		return
	}
	render.NoContent(w, r)
}

func renderInboundError(w http.ResponseWriter, r *http.Request, name string, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, listener.ErrInboundNotFound), errors.Is(err, listener.ErrInboundUserNotFound):
		status = http.StatusNotFound
	case errors.Is(err, C.ErrInboundUsersUnsupported):
		status = http.StatusConflict
		if typ := listener.InboundType(name); typ != "" {
			err = errors.New(err.Error() + " (type " + typ + ")")
		}
	case errors.Is(err, C.ErrInvalidInboundUser), errors.Is(err, listener.ErrInboundUserExists):
		status = http.StatusBadRequest
	}
	render.Status(r, status)
	render.JSON(w, r, newError(err.Error()))
}
