package xhttp

import (
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/http/httptrace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestPacketUpWriter(cfg *Config, transport http.RoundTripper, maxEachPostBytes int, interval Range) *PacketUpWriter {
	ctx, cancel := context.WithCancel(context.Background())
	writer := &PacketUpWriter{
		ctx:                  ctx,
		cancel:               cancel,
		cfg:                  cfg,
		scMaxEachPostBytes:   maxEachPostBytes,
		scMinPostsIntervalMs: interval,
		sessionID:            "session",
		transport:            transport,
		inflightSem:          make(chan struct{}, packetUpMaxInflightPosts),
	}
	writer.writeCond = sync.Cond{L: &writer.writeMu}
	return writer
}

// newPacketUpTestServer starts an HTTP/2 server that answers every packet-up POST after delay
// and reports the received payloads by seq.
func newPacketUpTestServer(t *testing.T, delay time.Duration, status int) (*httptest.Server, *sync.Map) {
	received := &sync.Map{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/xhttp/"), "/")
		if len(parts) == 2 {
			received.Store(parts[1], body)
		}
		time.Sleep(delay)
		w.WriteHeader(status)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, received
}

func TestPacketUpWriteReturnsAfterRequest(t *testing.T) {
	releaseResponse := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseResponse) })
	}
	t.Cleanup(release)

	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		httptrace.ContextClientTrace(req.Context()).WroteRequest(httptrace.WroteRequestInfo{})
		<-releaseResponse
		return &http.Response{
			Status:     "503 Service Unavailable",
			StatusCode: http.StatusServiceUnavailable,
			Body:       http.NoBody,
		}, nil
	})
	writer := newTestPacketUpWriter(&Config{Host: "example.com"}, transport, 1000, Range{30, 30})

	writeDone := make(chan error, 1)
	go func() {
		writer.writeMu.Lock()
		defer writer.writeMu.Unlock()
		_, err := writer.write([]byte("payload"))
		writeDone <- err
	}()

	select {
	case err := <-writeDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("packet upload waited for the response")
	}

	release()
	select {
	case <-writer.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("response error was not reported")
	}
	writer.writeMu.Lock()
	err := writer.flushErr
	writer.writeMu.Unlock()
	require.ErrorContains(t, err, "503")

	// the late error must fail the next Write
	_, err = writer.Write([]byte("more"))
	require.ErrorContains(t, err, "503")
}

func TestPacketUpTransportErrorFailsNextWrite(t *testing.T) {
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("connection reset")
	})
	writer := newTestPacketUpWriter(&Config{Host: "example.com"}, transport, 1000, Range{1, 1})

	_, err := writer.Write([]byte("payload"))
	require.NoError(t, err) // buffered

	require.Eventually(t, func() bool {
		_, err := writer.Write([]byte("more"))
		return err != nil && strings.Contains(err.Error(), "connection reset")
	}, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, writer.Close())
}

func TestPacketUpNotSerializedOnResponseLatency(t *testing.T) {
	const (
		responseDelay = 300 * time.Millisecond
		posts         = 10
		postSize      = 1000
	)
	server, received := newPacketUpTestServer(t, responseDelay, http.StatusOK)

	cfg := &Config{Host: server.Listener.Addr().String(), Path: "/xhttp"}
	writer := newTestPacketUpWriter(cfg, server.Client().Transport, postSize, Range{1, 1})

	start := time.Now()
	payload := make([]byte, posts*postSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	n, err := writer.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	elapsed := time.Since(start)

	// Waiting for each response would take posts*responseDelay (3s).
	assert.Less(t, elapsed, posts*responseDelay/2, "packet-up uploads are serialized on the response latency")

	require.NoError(t, writer.Close())

	var got []byte
	for i := 0; i < posts; i++ {
		v, ok := received.Load(strconv.Itoa(i))
		require.True(t, ok, "seq %d not received", i)
		got = append(got, v.([]byte)...)
	}
	assert.Equal(t, payload, got)
}

func TestPacketUpFirstPacketNotDelayed(t *testing.T) {
	var requests atomic.Int32
	firstRequest := make(chan time.Time, 1)
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if requests.Add(1) == 1 {
			firstRequest <- time.Now()
		}
		return &http.Response{Status: "200 OK", StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	interval := 500 * time.Millisecond
	writer := newTestPacketUpWriter(&Config{Host: "example.com"}, transport, 1000, Range{int(interval.Milliseconds()), int(interval.Milliseconds())})
	defer writer.Close()

	start := time.Now()
	_, err := writer.Write([]byte("first"))
	require.NoError(t, err)

	select {
	case at := <-firstRequest:
		assert.Less(t, at.Sub(start), interval/2, "the first packet waited for the whole sc-min-posts-interval-ms")
	case <-time.After(2 * time.Second):
		t.Fatal("first packet was not sent")
	}

	// the next packet must still respect the interval since the previous POST
	_, err = writer.Write([]byte("second"))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return requests.Load() == 2 }, 2*time.Second, 5*time.Millisecond)
	assert.GreaterOrEqual(t, time.Since(start), interval-50*time.Millisecond)
}

func TestPacketUpCloseWaitsForInflightAndRejectsWrites(t *testing.T) {
	server, received := newPacketUpTestServer(t, 200*time.Millisecond, http.StatusOK)

	cfg := &Config{Host: server.Listener.Addr().String(), Path: "/xhttp"}
	writer := newTestPacketUpWriter(cfg, server.Client().Transport, 1000, Range{1, 1})

	_, err := writer.Write([]byte("last words"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	v, ok := received.Load("0")
	require.True(t, ok, "the buffered packet was not flushed on Close")
	assert.Equal(t, []byte("last words"), v)

	// no goroutine is left behind
	done := make(chan struct{})
	go func() {
		writer.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("in-flight requests are still running after Close")
	}

	writer.writeMu.Lock()
	err = writer.flushErr
	writer.writeMu.Unlock()
	require.Error(t, err) // the response error of a canceled request doesn't matter, but the writer is closed

	_, err = writer.Write([]byte("after close"))
	require.Error(t, err)
}

func TestPacketUpPathWithQuery(t *testing.T) {
	var gotURL atomic.Value
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		gotURL.Store(req.URL.String())
		return &http.Response{Status: "200 OK", StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	writer := newTestPacketUpWriter(&Config{Host: "example.com", Path: "/xhttp?ed=2048&a=b"}, transport, 1000, Range{1, 1})
	writer.writeMu.Lock()
	_, err := writer.write([]byte("payload"))
	writer.writeMu.Unlock()
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	assert.Equal(t, "https://example.com/xhttp/session/0?ed=2048&a=b", gotURL.Load())
}

func TestPacketUpWaitsForResponseOverHTTP1(t *testing.T) {
	assert.True(t, isHTTP1Transport(&http1Transport{&http.Transport{}}))
	assert.True(t, isHTTP1Transport(onlyRoundTripper{&http1Transport{&http.Transport{}}}))
	assert.True(t, isHTTP1Transport(&ReuseTransport{entry: &reuseEntry{transport: &http1Transport{&http.Transport{}}}}))
	assert.False(t, isHTTP1Transport(&http.Transport{}))

	const responseDelay = 100 * time.Millisecond
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		time.Sleep(responseDelay)
		return &http.Response{Status: "200 OK", StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	writer := newTestPacketUpWriter(&Config{Host: "example.com"}, transport, 1000, Range{1, 1})
	writer.waitResponse = true

	start := time.Now()
	writer.writeMu.Lock()
	_, err := writer.write([]byte("payload"))
	writer.writeMu.Unlock()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, time.Since(start), responseDelay)
	require.NoError(t, writer.Close())
}
