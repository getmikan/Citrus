package route

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	stdhttp "net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func issueWSTestTicket(t *testing.T, handler http.Handler, path, origin string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"path": path})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/ws-ticket", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+testSecret)
	req.Header.Set("Origin", origin)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func wsTestTicketValue(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	if response.Code != http.StatusCreated {
		t.Fatalf("issue ticket: %d %s", response.Code, response.Body)
	}
	var result struct {
		Ticket    string `json:"ticket"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(result.Ticket)
	if err != nil || len(decoded) != wsTicketBytes || result.ExpiresIn != 30 {
		t.Fatal("ticket has invalid entropy or expiry")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("ticket response can be cached")
	}
	if strings.Contains(response.Body.String(), testSecret) {
		t.Fatal("response exposed controller secret")
	}
	return result.Ticket
}

func wsAuthStatus(a *controllerAuth, method, path, origin string, upgrade bool) int {
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("Origin", origin)
	if upgrade {
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Connection", "keep-alive, Upgrade")
	}
	rr := httptest.NewRecorder()
	a.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(rr, r)
	return rr.Code
}

func TestWSTicketIssuanceRequiresBearerAndHasBoundedInput(t *testing.T) {
	h := newHandler(&Config{Secret: testSecret})
	for _, token := range []string{"", "wrong"} {
		r := httptest.NewRequest(http.MethodPost, "/auth/ws-ticket", strings.NewReader(`{"path":"/events"}`))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("issued without bearer: %d", rr.Code)
		}
	}
	for _, path := range []string{"/configs", "/debug/pprof/", "https://example.com/events", "//example.com/events", "/events#fragment", "/events?token=" + testSecret, "/events?ticket=x", "/%65vents", "/events?types=" + strings.Repeat("x", maxWSTicketRequestBytes)} {
		if rr := issueWSTestTicket(t, h, path, ""); rr.Code != http.StatusBadRequest {
			t.Errorf("accepted invalid ticket scope %q: %d", path, rr.Code)
		}
	}
	wsTestTicketValue(t, issueWSTestTicket(t, h, "/events?types=auth", "https://panel.example"))
}

func TestWSTicketScopesOriginQueryMethodAndUpgrade(t *testing.T) {
	a := newControllerAuth(testSecret, false)
	issue := a.middleware(http.HandlerFunc(a.issueTicket))
	token := wsTestTicketValue(t, issueWSTestTicket(t, issue, "/events?types=auth", "https://panel.example"))
	for _, tc := range []struct {
		method, path, origin string
		upgrade              bool
	}{
		{http.MethodGet, "/logs?ticket=" + token, "https://panel.example", true},
		{http.MethodGet, "/events?types=config.reload&ticket=" + token, "https://panel.example", true},
		{http.MethodGet, "/events?types=auth&ticket=" + token, "https://other.example", true},
		{http.MethodPost, "/events?types=auth&ticket=" + token, "https://panel.example", true},
		{http.MethodGet, "/events?types=auth&ticket=" + token, "https://panel.example", false},
		{http.MethodGet, "/events?types=auth&ticket=" + token + "&ticket=" + token, "https://panel.example", true},
		{http.MethodGet, "/auth/ws-ticket?ticket=" + token, "https://panel.example", true},
	} {
		if got := wsAuthStatus(a, tc.method, tc.path, tc.origin, tc.upgrade); got != http.StatusUnauthorized {
			t.Errorf("ticket escaped scope: %s %s => %d", tc.method, tc.path, got)
		}
	}
	valid := "/events?ticket=" + token + "&types=auth"
	if got := wsAuthStatus(a, http.MethodGet, valid, "https://panel.example", true); got != http.StatusNoContent {
		t.Fatalf("valid ticket refused: %d", got)
	}
	if got := wsAuthStatus(a, http.MethodGet, valid, "https://panel.example", true); got != http.StatusUnauthorized {
		t.Fatal("replayed ticket accepted")
	}
}

func TestWSTicketConcurrentRedemptionHasOneWinner(t *testing.T) {
	a := newControllerAuth(testSecret, false)
	token := wsTestTicketValue(t, issueWSTestTicket(t, a.middleware(http.HandlerFunc(a.issueTicket)), "/traffic", ""))
	var winners atomic.Int32
	var wg sync.WaitGroup
	for n := 0; n < 32; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if wsAuthStatus(a, http.MethodGet, "/traffic?ticket="+token, "", true) == http.StatusNoContent {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("ticket had %d successful redemptions", winners.Load())
	}
}

func TestWSTicketExpiryCapacityAndRouterIsolation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := newControllerAuth(testSecret, false)
	a.limit = 1
	a.now = func() time.Time { return now }
	issue := a.middleware(http.HandlerFunc(a.issueTicket))
	token := wsTestTicketValue(t, issueWSTestTicket(t, issue, "/memory", ""))
	if rr := issueWSTestTicket(t, issue, "/memory", ""); rr.Code != http.StatusTooManyRequests {
		t.Fatal("pending ticket cap bypassed")
	}
	if len(a.tickets) != 1 {
		t.Fatal("ticket cap evicted an unexpired ticket")
	}
	newRouter := newControllerAuth(testSecret, false)
	if wsAuthStatus(newRouter, http.MethodGet, "/memory?ticket="+token, "", true) != http.StatusUnauthorized {
		t.Fatal("old-generation ticket accepted")
	}
	now = now.Add(wsTicketLifetime)
	// Issuance itself reclaims expired entries; a client need not redeem them.
	wsTestTicketValue(t, issueWSTestTicket(t, issue, "/memory", ""))
	if wsAuthStatus(a, http.MethodGet, "/memory?ticket="+token, "", true) != http.StatusUnauthorized {
		t.Fatal("expired ticket accepted")
	}
}

func TestWSTicketConcurrentIssuanceRespectsCapacity(t *testing.T) {
	a := newControllerAuth(testSecret, false)
	a.limit = 2
	issue := a.middleware(http.HandlerFunc(a.issueTicket))
	var issued atomic.Int32
	var wg sync.WaitGroup
	for n := 0; n < 16; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if issueWSTestTicket(t, issue, "/events", "").Code == http.StatusCreated {
				issued.Add(1)
			}
		}()
	}
	wg.Wait()
	if issued.Load() != 2 || len(a.tickets) != 2 {
		t.Fatalf("capacity bypassed: issued=%d stored=%d", issued.Load(), len(a.tickets))
	}
}

func TestLegacyWebSocketOptionControlsRealUpgrade(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		srv := httptest.NewServer(newHandler(&Config{Secret: testSecret, AllowLegacyWebSocketToken: enabled}))
		func() {
			defer srv.Close()
			conn, err := net.Dial("tcp", srv.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := fmt.Fprintf(conn, "GET /events?token=%s HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", testSecret); err != nil {
				t.Fatal(err)
			}
			response, err := stdhttp.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			want := stdhttp.StatusUnauthorized
			if enabled {
				want = stdhttp.StatusSwitchingProtocols
			}
			if response.StatusCode != want {
				t.Fatalf("legacy=%v: got %d, want %d", enabled, response.StatusCode, want)
			}
		}()
	}
}

func TestLegacyWebSocketMainSecretRequiresOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		a := newControllerAuth(testSecret, enabled)
		want := http.StatusUnauthorized
		if enabled {
			want = http.StatusNoContent
		}
		if got := wsAuthStatus(a, http.MethodGet, "/logs?token="+testSecret, "", true); got != want {
			t.Fatalf("legacy=%v: %d", enabled, got)
		}
		for _, tc := range []struct {
			method, path string
			upgrade      bool
		}{
			{http.MethodPost, "/configs?token=" + testSecret, true},
			{http.MethodGet, "/debug/pprof/?token=" + testSecret, true},
			{http.MethodGet, "/logs?token=" + testSecret, false},
		} {
			if got := wsAuthStatus(a, tc.method, tc.path, "", tc.upgrade); got != http.StatusUnauthorized {
				t.Fatal("legacy URL secret authorized a non-WebSocket request")
			}
		}
	}
}
