package route

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/eventbus"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type streamedEvent struct {
	Type string          `json:"type"`
	Time time.Time       `json:"time"`
	Data json.RawMessage `json:"data"`
}

func eventsServer(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(router(false, testSecret, "", Cors{}))
	t.Cleanup(srv.Close)
	return srv
}

// openEvents opens a chunked stream; the subscription exists once it returns.
func openEvents(t *testing.T, srv *httptest.Server, query, accept string) (*bufio.Reader, func()) {
	t.Helper()
	req, err := stdhttp.NewRequest(stdhttp.MethodGet, srv.URL+"/events"+query, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testSecret)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := stdhttp.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, stdhttp.StatusOK, resp.StatusCode)
	return bufio.NewReader(resp.Body), func() { _ = resp.Body.Close() }
}

func readLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := r.ReadString('\n')
		ch <- result{line, err}
	}()
	select {
	case res := <-ch:
		require.NoError(t, res.err)
		return strings.TrimRight(res.line, "\n")
	case <-time.After(3 * time.Second):
		t.Fatal("no event on the stream")
		return ""
	}
}

func readEvent(t *testing.T, r *bufio.Reader) streamedEvent {
	t.Helper()
	var e streamedEvent
	line := readLine(t, r)
	require.NoError(t, json.Unmarshal([]byte(line), &e), line)
	return e
}

func TestEventsRequests(t *testing.T) {
	h := router(false, testSecret, "", Cors{})
	code, _ := serveJSON(t, h, stdhttp.MethodGet, "/events", "", "")
	assert.Equal(t, stdhttp.StatusUnauthorized, code, "behind the controller secret")
	code, body := serveJSON(t, h, stdhttp.MethodGet, "/events?types=auth,bogus", testSecret, "")
	assert.Equal(t, stdhttp.StatusBadRequest, code)
	assert.Contains(t, body, "bogus")
}

func TestEventsChunkedRealHooks(t *testing.T) {
	const uuidA, uuidB = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	name := fmt.Sprintf("ev-vless-%d", time.Now().UnixNano())
	vless, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:    inbound.BaseOption{NameStr: name, Listen: "127.0.0.1", Port: "0"},
		Users:         []inbound.VlessUser{{Username: "alice", UUID: uuidA}},
		AllowInsecure: true,
	})
	require.NoError(t, err)

	srv := eventsServer(t)
	r, closeStream := openEvents(t, srv, "?types=user.changed,user.limit,inbound.state", "")
	defer closeStream()

	// inbound.state: the listener starts
	listener.PatchInboundListeners(map[string]C.InboundListener{name: vless}, tunnel.Tunnel, false)
	t.Cleanup(func() { listener.PatchInboundListeners(nil, tunnel.Tunnel, true) })
	e := readEvent(t, r)
	require.Equal(t, eventbus.TypeInboundState, e.Type)
	var state eventbus.InboundState
	require.NoError(t, json.Unmarshal(e.Data, &state))
	assert.Equal(t, eventbus.InboundState{Inbound: name, Type: "vless", State: eventbus.InboundStarted}, state)

	// a type that is not subscribed does not show
	eventbus.PublishConfigReload(nil)

	// user.changed: a user added with the runtime users API
	h := router(false, testSecret, "", Cors{})
	code, body := serveJSON(t, h, stdhttp.MethodPost, "/inbounds/"+name+"/users", testSecret, `{"name":"bob","secret":"`+uuidB+`"}`)
	require.Equal(t, stdhttp.StatusCreated, code, body)
	e = readEvent(t, r)
	require.Equal(t, eventbus.TypeUserChanged, e.Type)
	assert.JSONEq(t, `{"inbound":"`+name+`","added":["bob"]}`, string(e.Data))
	assert.WithinDuration(t, time.Now(), e.Time, time.Minute)

	code, _ = serveJSON(t, h, stdhttp.MethodDelete, "/inbounds/"+name+"/users/bob", testSecret, "")
	require.Equal(t, stdhttp.StatusNoContent, code)
	e = readEvent(t, r)
	assert.JSONEq(t, `{"inbound":"`+name+`","removed":["bob"]}`, string(e.Data))

	// user.limit: max-conns refuses a connection
	um := statistic.DefaultManager.Users()
	require.NoError(t, um.SetLimit(statistic.UserLimit{Inbound: name, User: "alice", MaxConns: 1}))
	t.Cleanup(func() { um.DeleteLimit(statistic.UserKey{Inbound: name, User: "alice"}) })
	key, ip := statistic.UserKey{Inbound: name, User: "alice"}, netip.MustParseAddr("192.0.2.10")
	c, err := um.Admit(key, ip)
	require.NoError(t, err)
	defer um.Release(c, ip)
	_, err = um.Admit(key, ip)
	require.Error(t, err)
	e = readEvent(t, r)
	require.Equal(t, eventbus.TypeUserLimit, e.Type)
	assert.JSONEq(t, `{"inbound":"`+name+`","user":"alice","reason":"max-conns","action":"rejected","detail":"max-conns 1 reached","remote":"192.0.2.10"}`, string(e.Data))

	// inbound.state: the listener stops
	listener.PatchInboundListeners(nil, tunnel.Tunnel, true)
	e = readEvent(t, r)
	assert.JSONEq(t, `{"inbound":"`+name+`","type":"vless","state":"stopped"}`, string(e.Data))
}

func TestEventsSSE(t *testing.T) {
	srv := eventsServer(t)
	r, closeStream := openEvents(t, srv, "?types=provider.update", "text/event-stream")
	defer closeStream()
	eventbus.Publish(eventbus.TypeProviderUpdate, eventbus.ProviderUpdate{Name: "p", Status: eventbus.StatusOK, Changed: true})
	assert.Equal(t, "event: provider.update", readLine(t, r))
	data := readLine(t, r)
	require.True(t, strings.HasPrefix(data, "data: "), data)
	var e streamedEvent
	require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(data, "data: ")), &e))
	assert.JSONEq(t, `{"name":"p","status":"ok","changed":true}`, string(e.Data))
	assert.Equal(t, "", readLine(t, r))
}

func TestEventsDropped(t *testing.T) {
	oldBuf, oldInterval := eventsBuffer, eventsDroppedInterval
	eventsBuffer, eventsDroppedInterval = 1, 50*time.Millisecond
	t.Cleanup(func() { eventsBuffer, eventsDroppedInterval = oldBuf, oldInterval })

	srv := eventsServer(t)
	r, closeStream := openEvents(t, srv, "?types=config.reload", "")
	defer closeStream()
	for i := 0; i < 1000; i++ {
		eventbus.PublishConfigReload(nil)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		e := readEvent(t, r)
		if e.Type == eventbus.TypeDropped {
			var d eventbus.Dropped
			require.NoError(t, json.Unmarshal(e.Data, &d))
			assert.Greater(t, d.Count, uint64(0))
			return
		}
		require.Equal(t, eventbus.TypeConfigReload, e.Type)
	}
	t.Fatal("no dropped event")
}

// wsReadText reads one unmasked server text frame.
func wsReadText(r io.Reader) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0]&0x0f != 0x1 {
		return "", errors.New("not a text frame")
	}
	n := uint64(hdr[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return string(buf), err
}

func TestEventsWebSocket(t *testing.T) {
	srv := eventsServer(t)
	before := eventbus.Default.Subscribers()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// A browser exchanges its bearer secret for a short-lived scoped ticket.
	req, err := stdhttp.NewRequest(stdhttp.MethodPost, srv.URL+"/auth/ws-ticket", strings.NewReader(`{"path":"/events?types=config.reload"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testSecret)
	response, err := stdhttp.DefaultClient.Do(req)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, stdhttp.StatusCreated, response.StatusCode)
	var issued struct {
		Ticket string `json:"ticket"`
	}
	require.NoError(t, json.NewDecoder(response.Body).Decode(&issued))
	_, err = fmt.Fprintf(conn, "GET /events?types=config.reload&ticket=%s HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", issued.Ticket)
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	resp, err := stdhttp.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, stdhttp.StatusSwitchingProtocols, resp.StatusCode)
	assert.Equal(t, before+1, eventbus.Default.Subscribers())

	eventbus.PublishConfigReload(errors.New("bad yaml"))
	msg, err := wsReadText(br)
	require.NoError(t, err)
	var e streamedEvent
	require.NoError(t, json.Unmarshal([]byte(msg), &e))
	assert.Equal(t, eventbus.TypeConfigReload, e.Type)
	assert.JSONEq(t, `{"status":"error","error":"bad yaml"}`, string(e.Data))

	// the client goes away: the subscription is released
	_ = conn.Close()
	require.Eventually(t, func() bool { return eventbus.Default.Subscribers() == before }, 3*time.Second, 10*time.Millisecond)
}
