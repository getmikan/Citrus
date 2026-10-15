package trusttunnel

import (
	"context"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/authevent"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/sing/common/logger"
)

func TestServeHTTPEmitsAuthEvent(t *testing.T) {
	events := make(chan authevent.Event, 4)
	authevent.SetHandler(func(e authevent.Event) { events <- e })
	t.Cleanup(func() { authevent.SetHandler(nil) })

	service := NewService(ServiceOptions{Ctx: context.Background(), Logger: logger.NOP()})
	service.UpdateUsers(map[string]string{"user": "secret"})
	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}

	serve := func(method, authorization string) int {
		request := httptest.NewRequest(method, "https://example.com/", nil)
		request.RemoteAddr = "192.0.2.1:50000"
		request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, net.Addr(local)))
		if authorization != "" {
			request.Header.Set("Proxy-Authorization", authorization)
		}
		recorder := httptest.NewRecorder()
		service.ServeHTTP(recorder, request)
		return recorder.Code
	}
	basic := func(username, password string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	}
	expect := func(reason string) {
		t.Helper()
		select {
		case e := <-events:
			want := authevent.Event{Protocol: "trusttunnel", Local: local.String(), Remote: "192.0.2.1:50000", Reason: reason, Method: http.MethodConnect}
			if e != want {
				t.Fatalf("got %+v, want %+v", e, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no %s event", reason)
		}
	}

	if code := serve(http.MethodConnect, ""); code != http.StatusProxyAuthRequired {
		t.Fatalf("no credentials: status %d", code)
	}
	expect(authevent.ReasonNoCredentials)

	if code := serve(http.MethodConnect, basic("user", "wrong")); code != http.StatusProxyAuthRequired {
		t.Fatalf("wrong password: status %d", code)
	}
	expect(authevent.ReasonWrongCredentials)

	if code := serve(http.MethodConnect, basic("nobody", "secret")); code != http.StatusProxyAuthRequired {
		t.Fatalf("unknown user: status %d", code)
	}
	expect(authevent.ReasonWrongCredentials)

	// Valid credentials are not reported, whatever happens to the request next.
	if code := serve(http.MethodGet, basic("user", "secret")); code != http.StatusMethodNotAllowed {
		t.Fatalf("valid credentials: status %d", code)
	}
	select {
	case e := <-events:
		t.Fatalf("event for valid credentials: %+v", e)
	case <-time.After(100 * time.Millisecond):
	}
}

// With a fallback, requests without credentials are cover-site visits and are
// not reported; wrong credentials still are.
func TestServeHTTPAuthEventWithFallback(t *testing.T) {
	events := make(chan authevent.Event, 4)
	authevent.SetHandler(func(e authevent.Event) { events <- e })
	t.Cleanup(func() { authevent.SetHandler(nil) })

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("cover"))
	}))
	t.Cleanup(backend.Close)
	service := newFallbackService(t, backend)
	service.UpdateUsers(map[string]string{"user": "secret"})

	serve := func(method, authorization string) int {
		request := httptest.NewRequest(method, "https://example.com/", nil)
		request.RemoteAddr = "192.0.2.1:50000"
		if authorization != "" {
			request.Header.Set("Proxy-Authorization", authorization)
		}
		recorder := httptest.NewRecorder()
		service.ServeHTTP(recorder, request)
		return recorder.Code
	}

	if code := serve(http.MethodGet, ""); code != http.StatusOK {
		t.Fatalf("cover page: status %d", code)
	}
	select {
	case e := <-events:
		t.Fatalf("cover-site visit reported: %+v", e)
	case <-time.After(100 * time.Millisecond):
	}

	serve(http.MethodGet, "Basic "+base64.StdEncoding.EncodeToString([]byte("user:wrong")))
	select {
	case e := <-events:
		if e.Reason != authevent.ReasonWrongCredentials {
			t.Fatalf("got %+v, want wrong_credentials", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wrong credentials not reported")
	}
}
