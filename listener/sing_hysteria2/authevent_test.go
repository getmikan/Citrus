package sing_hysteria2

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/authevent"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestAuthEventHandler(t *testing.T) {
	events := make(chan authevent.Event, 8)
	authevent.SetHandler(func(e authevent.Event) { events <- e })
	t.Cleanup(func() { authevent.SetHandler(nil) })

	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}
	request := func(method, path, auth, rx string) *http.Request {
		r := httptest.NewRequest(method, "https://hysteria"+path, nil)
		r.RemoteAddr = "192.0.2.1:50000"
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, net.Addr(local)))
		if auth != "" {
			r.Header.Set(authHeader, auth)
		}
		if rx != "" {
			r.Header.Set(authCCRXName, rx)
		}
		return r
	}
	expect := func(reason string) {
		t.Helper()
		select {
		case e := <-events:
			want := authevent.Event{Protocol: "hysteria2", Local: local.String(), Remote: "192.0.2.1:50000", Reason: reason, Method: http.MethodPost}
			if e != want {
				t.Fatalf("got %+v, want %+v", e, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no %s event", reason)
		}
	}
	expectNone := func() {
		t.Helper()
		select {
		case e := <-events:
			t.Fatalf("unexpected event %+v", e)
		case <-time.After(100 * time.Millisecond):
		}
	}

	covered := 0
	cover := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		covered++
		w.WriteHeader(http.StatusTeapot)
	})

	handler := authEventHandler(cover, 0, false)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request(http.MethodPost, authPath, "", ""))
	if recorder.Code != http.StatusTeapot {
		t.Fatalf("cover not served: %d", recorder.Code)
	}
	expect(authevent.ReasonNoCredentials)

	handler.ServeHTTP(httptest.NewRecorder(), request(http.MethodPost, authPath, "wrong", "0"))
	expect(authevent.ReasonWrongCredentials)

	// Ordinary masquerade traffic is not an auth attempt.
	handler.ServeHTTP(httptest.NewRecorder(), request(http.MethodGet, "/", "", ""))
	handler.ServeHTTP(httptest.NewRecorder(), request(http.MethodPost, "/other", "x", ""))
	expectNone()

	// A server with a receive bandwidth and ignore-client-bandwidth also
	// masquerades its own users asking for BBR; those must not be reported.
	handler = authEventHandler(cover, 1000000, true)
	handler.ServeHTTP(httptest.NewRecorder(), request(http.MethodPost, authPath, "maybe-valid", "0"))
	expectNone()
	handler.ServeHTTP(httptest.NewRecorder(), request(http.MethodPost, authPath, "wrong", "100"))
	expect(authevent.ReasonWrongCredentials)

	if covered != 6 {
		t.Fatalf("cover served %d times, want 6", covered)
	}

	// No cover handler: sing-quic's default 404.
	recorder = httptest.NewRecorder()
	authEventHandler(nil, 0, false).ServeHTTP(recorder, request(http.MethodGet, "/", "", ""))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("default cover: %d", recorder.Code)
	}
}
