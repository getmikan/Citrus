package xhttp

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerHandlerModeRestrictions(t *testing.T) {
	testCases := []struct {
		name       string
		mode       string
		method     string
		target     string
		wantStatus int
	}{
		{
			name:       "StreamOneAcceptsStreamOne",
			mode:       "stream-one",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/",
			wantStatus: http.StatusOK,
		},
		{
			name:       "StreamOneRejectsSessionDownload",
			mode:       "stream-one",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "StreamUpAcceptsStreamOne",
			mode:       "stream-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/",
			wantStatus: http.StatusOK,
		},
		{
			name:       "StreamUpAllowsDownloadEndpoint",
			mode:       "stream-up",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session",
			wantStatus: http.StatusOK,
		},
		{
			name:       "StreamUpRejectsPacketUpload",
			mode:       "stream-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/session/0",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "PacketUpAllowsDownloadEndpoint",
			mode:       "packet-up",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session",
			wantStatus: http.StatusOK,
		},
		{
			name:       "PacketUpAcceptsPostUpload",
			mode:       "packet-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/session/0",
			wantStatus: http.StatusOK,
		},
		{
			name:       "PacketUpAcceptsGetUpload",
			mode:       "packet-up",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session/0",
			wantStatus: http.StatusOK,
		},
		{
			name:       "PacketUpAcceptsPutUpload",
			mode:       "packet-up",
			method:     http.MethodPut,
			target:     "https://example.com/xhttp/session/0",
			wantStatus: http.StatusOK,
		},
		{
			name:       "AutoAcceptsGetUpload",
			mode:       "auto",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session/0",
			wantStatus: http.StatusOK,
		},
		{
			name:       "StreamUpRejectsGetPacketUpload",
			mode:       "stream-up",
			method:     http.MethodGet,
			target:     "https://example.com/xhttp/session/0",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "PacketUpRejectsStreamOne",
			mode:       "packet-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "PacketUpRejectsStreamUpUpload",
			mode:       "packet-up",
			method:     http.MethodPost,
			target:     "https://example.com/xhttp/session",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			config := Config{
				Path: "/xhttp",
				Mode: testCase.mode,
			}
			handler, err := NewServerHandler(ServerOption{
				Config: config,
				ConnHandler: func(conn net.Conn, r *http.Request) {
					_ = conn.Close()
				},
			})
			assert.NoError(t, err)

			req := httptest.NewRequest(testCase.method, testCase.target, io.NopCloser(http.NoBody))
			recorder := httptest.NewRecorder()

			err = config.FillStreamRequest(req, "")
			assert.NoError(t, err)

			handler.ServeHTTP(recorder, req)

			assert.Equal(t, testCase.wantStatus, recorder.Result().StatusCode)
		})
	}
}

// Packet-up uploads with any method and data placement reach the session, with
// the server's uplink-data-placement unset ("auto") or naming the placement, and
// the default uplink-data-key / x-padding-obfs-mode settings on both sides (Xray-core's).
func TestServerHandlerPacketUpUploadPlacements(t *testing.T) {
	payload := bytes.Repeat([]byte("citrus-xhttp-"), 700) // ~9 KiB, several header chunks
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPost} {
		for _, placement := range []string{PlacementBody, PlacementHeader, PlacementCookie} {
			for _, serverPlacement := range []string{"", placement} {
				for _, obfs := range []bool{false, true} {
					name := fmt.Sprintf("%s/%s/server=%q/obfs=%v", method, placement, serverPlacement, obfs)
					t.Run(name, func(t *testing.T) {
						serverConfig := Config{
							Path:                "/xhttp",
							Mode:                "packet-up",
							UplinkDataPlacement: serverPlacement,
							XPaddingObfsMode:    obfs,
						}
						clientConfig := Config{
							Path:                "/xhttp",
							Mode:                "packet-up",
							UplinkHTTPMethod:    method,
							UplinkDataPlacement: placement,
							XPaddingObfsMode:    obfs,
						}
						handler, err := NewServerHandler(ServerOption{
							Config:      serverConfig,
							ConnHandler: func(conn net.Conn, r *http.Request) { _ = conn.Close() },
						})
						require.NoError(t, err)

						req := httptest.NewRequest(clientConfig.GetNormalizedUplinkHTTPMethod(), "https://example.com/xhttp", nil)
						require.NoError(t, clientConfig.FillPacketRequest(req, "session", "0", payload))
						if req.Body == nil {
							req.Body = http.NoBody
						}
						if placement == PlacementHeader {
							assert.NotEmpty(t, req.Header.Get("X-Data-0"))
						}
						recorder := httptest.NewRecorder()
						handler.ServeHTTP(recorder, req)

						result := recorder.Result()
						require.Equal(t, http.StatusOK, result.StatusCode)
						if method == http.MethodGet || placement != PlacementBody {
							assert.Equal(t, "no-store", result.Header.Get("Cache-Control"))
						}

						session := handler.(*requestHandler).getSession("session")
						require.NotNil(t, session)
						got := make([]byte, len(payload))
						_, err = io.ReadFull(session.uploadQueue, got)
						require.NoError(t, err)
						assert.Equal(t, payload, got)
						_ = session.uploadQueue.Close()
					})
				}
			}
		}
	}
}

// A server that names a placement reads only that placement, as in Xray-core.
func TestServerHandlerPacketUpUploadWrongPlacement(t *testing.T) {
	handler, err := NewServerHandler(ServerOption{
		Config:      Config{Path: "/xhttp", Mode: "packet-up", UplinkDataPlacement: PlacementBody},
		ConnHandler: func(conn net.Conn, r *http.Request) { _ = conn.Close() },
	})
	require.NoError(t, err)
	clientConfig := Config{Path: "/xhttp", Mode: "packet-up", UplinkDataPlacement: PlacementHeader}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/xhttp", nil)
	require.NoError(t, clientConfig.FillPacketRequest(req, "session", "0", []byte("data")))
	req.Body = http.NoBody
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	require.Equal(t, http.StatusOK, recorder.Result().StatusCode)

	session := handler.(*requestHandler).getSession("session")
	require.NotNil(t, session)
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = session.uploadQueue.Close()
	}()
	n, _ := session.uploadQueue.Read(make([]byte, 16))
	assert.Equal(t, 0, n)
}

func TestReadPacketBody(t *testing.T) {
	const limit = 1 << 20
	big := bytes.Repeat([]byte{'x'}, 200<<10)

	// declared length, large: pooled, given back by release
	payload, release, err := readPacketBody(bytes.NewReader(big), int64(len(big)), limit)
	require.NoError(t, err)
	require.NotNil(t, release)
	assert.Equal(t, big, payload)
	release()

	// declared length, small: exact allocation, nothing to release
	payload, release, err = readPacketBody(bytes.NewReader([]byte("hello")), 5, limit)
	require.NoError(t, err)
	assert.Nil(t, release)
	assert.Equal(t, "hello", string(payload))

	// empty body
	payload, release, err = readPacketBody(bytes.NewReader(nil), 0, limit)
	require.NoError(t, err)
	assert.Nil(t, release)
	assert.Empty(t, payload)

	// unknown length: read up to limit+1, the caller checks the size
	payload, release, err = readPacketBody(bytes.NewReader(big), -1, 1000)
	require.NoError(t, err)
	assert.Nil(t, release)
	assert.Len(t, payload, 1001)

	// body shorter than declared
	_, _, err = readPacketBody(bytes.NewReader(big[:100<<10]), int64(len(big)), limit)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

// Packet-up bodies read into pooled buffers reach the inner reader intact and
// in order, also when a buffer is reused for the next POST.
func TestServerPacketUpPooledBodies(t *testing.T) {
	config := Config{Path: "/xhttp", Mode: "packet-up"}
	handler, err := NewServerHandler(ServerOption{
		Config: config,
		ConnHandler: func(conn net.Conn, r *http.Request) {
			_ = conn.Close()
		},
	})
	require.NoError(t, err)
	h := handler.(*requestHandler)

	var want []byte
	for seq := 0; seq < 4; seq++ {
		body := bytes.Repeat([]byte{byte('a' + seq)}, 100<<10+seq)
		want = append(want, body...)
		req := httptest.NewRequest(http.MethodPost, "https://example.com/xhttp", nil)
		require.NoError(t, config.FillPacketRequest(req, "session", fmt.Sprint(seq), body))
		recorder := httptest.NewRecorder()
		h.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusOK, recorder.Result().StatusCode)

		// drain packet seq before the next POST, so its buffer can be reused
		s := h.getSession("session")
		require.NotNil(t, s)
		got := make([]byte, 0, len(body))
		buf := make([]byte, 32<<10)
		for len(got) < len(body) {
			n, err := s.uploadQueue.Read(buf)
			require.NoError(t, err)
			got = append(got, buf[:n]...)
		}
		require.Equal(t, body, got)
	}
	h.deleteSession("session", h.getSession("session"))
}
