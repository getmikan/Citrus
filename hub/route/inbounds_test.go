package route

import (
	"encoding/json"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func serveJSON(t *testing.T, h http.Handler, method, path, token, body string) (int, string) {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestInboundUsersAPI(t *testing.T) {
	const uuidA, uuidB, uuidC = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333"
	vless, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:    inbound.BaseOption{NameStr: "api-vless", Listen: "127.0.0.1", Port: "0"},
		Users:         []inbound.VlessUser{{Username: "alice", UUID: uuidA, Flow: "xtls-rprx-vision"}},
		AllowInsecure: true,
	})
	require.NoError(t, err)
	tun, err := inbound.NewTunnel(&inbound.TunnelOption{
		BaseOption: inbound.BaseOption{NameStr: "api-tunnel", Listen: "127.0.0.1", Port: "0"},
		Network:    []string{"tcp"},
		Target:     "127.0.0.1:1",
	})
	require.NoError(t, err)
	listener.PatchInboundListeners(map[string]C.InboundListener{vless.Name(): vless, tun.Name(): tun}, tunnel.Tunnel, false)
	t.Cleanup(func() { listener.PatchInboundListeners(nil, tunnel.Tunnel, true) })

	h := router(false, testSecret, "", Cors{})
	const users = "/inbounds/api-vless/users"

	code, _ := serveJSON(t, h, http.MethodGet, users, "", "")
	assert.Equal(t, http.StatusUnauthorized, code, "behind the controller secret")
	code, _ = serveJSON(t, h, http.MethodPut, users, "wrong", `{"users":[]}`)
	assert.Equal(t, http.StatusUnauthorized, code)

	code, body := serveJSON(t, h, http.MethodGet, users, testSecret, "")
	require.Equal(t, http.StatusOK, code, body)
	assert.NotContains(t, body, uuidA, "GET never shows secrets")
	var list inboundUsersResponse
	require.NoError(t, json.Unmarshal([]byte(body), &list))
	assert.Equal(t, "api-vless", list.Inbound)
	assert.Equal(t, "vless", list.Type)
	assert.Equal(t, []inboundUserInfo{{Name: "alice", Flow: "xtls-rprx-vision"}}, list.Users)

	code, _ = serveJSON(t, h, http.MethodGet, "/inbounds/nope/users", testSecret, "")
	assert.Equal(t, http.StatusNotFound, code)

	// add
	code, body = serveJSON(t, h, http.MethodPost, users, testSecret, `{"name":"bob","secret":"`+uuidB+`"}`)
	assert.Equal(t, http.StatusCreated, code, body)
	assert.NotContains(t, body, uuidB)
	code, _ = serveJSON(t, h, http.MethodPost, users, testSecret, `{"name":"bob","secret":"`+uuidC+`"}`)
	assert.Equal(t, http.StatusBadRequest, code, "the name exists")
	code, _ = serveJSON(t, h, http.MethodPost, users, testSecret, `{"name":"carol","secret":"`+uuidA+`"}`)
	assert.Equal(t, http.StatusBadRequest, code, "the secret belongs to alice")
	code, _ = serveJSON(t, h, http.MethodPost, users, testSecret, `{"name":"","secret":"`+uuidC+`"}`)
	assert.Equal(t, http.StatusBadRequest, code, "no name")
	code, _ = serveJSON(t, h, http.MethodPost, users, testSecret, `{"name":"carol","secret":"`+uuidC+`","flow":"bogus"}`)
	assert.Equal(t, http.StatusBadRequest, code, "unknown flow")
	code, _ = serveJSON(t, h, http.MethodPost, users, testSecret, `not json`)
	assert.Equal(t, http.StatusBadRequest, code)
	code, _ = serveJSON(t, h, http.MethodPost, "/inbounds/nope/users", testSecret, `{"name":"x","secret":"y"}`)
	assert.Equal(t, http.StatusNotFound, code)

	got, err := listener.InboundUsers("api-vless")
	require.NoError(t, err)
	assert.Equal(t, []C.InboundUser{{Name: "alice", Secret: uuidA, Flow: "xtls-rprx-vision"}, {Name: "bob", Secret: uuidB}}, got)

	// change a secret / flow
	code, body = serveJSON(t, h, http.MethodPatch, users+"/bob", testSecret, `{"secret":"`+uuidC+`"}`)
	assert.Equal(t, http.StatusNoContent, code, body)
	code, _ = serveJSON(t, h, http.MethodPatch, users+"/alice", testSecret, `{"flow":""}`)
	assert.Equal(t, http.StatusNoContent, code)
	code, _ = serveJSON(t, h, http.MethodPatch, users+"/alice", testSecret, `{}`)
	assert.Equal(t, http.StatusBadRequest, code, "nothing to change")
	code, _ = serveJSON(t, h, http.MethodPatch, users+"/nobody", testSecret, `{"secret":"x"}`)
	assert.Equal(t, http.StatusNotFound, code)
	got, _ = listener.InboundUsers("api-vless")
	assert.Equal(t, []C.InboundUser{{Name: "alice", Secret: uuidA}, {Name: "bob", Secret: uuidC}}, got)

	// remove
	code, _ = serveJSON(t, h, http.MethodDelete, users+"/alice", testSecret, "")
	assert.Equal(t, http.StatusNoContent, code)
	code, _ = serveJSON(t, h, http.MethodDelete, users+"/alice", testSecret, "")
	assert.Equal(t, http.StatusNotFound, code)
	got, _ = listener.InboundUsers("api-vless")
	assert.Equal(t, []C.InboundUser{{Name: "bob", Secret: uuidC}}, got)

	// replace all
	code, _ = serveJSON(t, h, http.MethodPut, users, testSecret, `{"users":[{"name":"a","secret":"`+uuidA+`"},{"name":"b","secret":"`+uuidB+`"}]}`)
	assert.Equal(t, http.StatusNoContent, code)
	code, _ = serveJSON(t, h, http.MethodPut, users, testSecret, `{"users":[{"name":"a","secret":"`+uuidA+`"},{"name":"a","secret":"`+uuidB+`"}]}`)
	assert.Equal(t, http.StatusBadRequest, code)
	code, _ = serveJSON(t, h, http.MethodPut, users, testSecret, `{}`)
	assert.Equal(t, http.StatusBadRequest, code, "users is required")
	got, _ = listener.InboundUsers("api-vless")
	assert.Equal(t, []string{"a", "b"}, []string{got[0].Name, got[1].Name})
	code, _ = serveJSON(t, h, http.MethodPut, users, testSecret, `{"users":[]}`)
	assert.Equal(t, http.StatusNoContent, code, "an empty list is allowed: nobody connects")

	// an inbound without runtime users
	code, body = serveJSON(t, h, http.MethodPut, "/inbounds/api-tunnel/users", testSecret, `{"users":[]}`)
	assert.Equal(t, http.StatusConflict, code)
	assert.Contains(t, body, "tunnel")
	code, _ = serveJSON(t, h, http.MethodGet, "/inbounds/api-tunnel/users", testSecret, "")
	assert.Equal(t, http.StatusConflict, code)
}
