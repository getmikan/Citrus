package sing_vless

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listenTestH3 serves an echo of the request body over HTTP/3.
func listenTestH3(t *testing.T) *h3Listener {
	t.Helper()
	certificate, privateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair([]byte(certificate), []byte(privateKey))
	require.NoError(t, err)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write(body)
	})
	l, err := listenH3(pc, &tls.Config{Certificates: []tls.Certificate{cert}}, echo, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func h3ClientTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}
}

// A request stream whose header does not arrive within handshakeTimeout is
// reset, as ReadHeaderTimeout drops such a peer on TCP; before, it held a
// server goroutine for as long as the connection lived.
func TestH3RequestHeaderTimeout(t *testing.T) {
	shortHandshakeTimeout(t, 300*time.Millisecond)
	l := listenTestH3(t)

	for name, sent := range map[string][]byte{
		// a stream that sends nothing is not opened on the server at all
		"FrameTypeOnly": {0x01},
		// a HEADERS frame of 16 bytes, 2 of them sent
		"PartialHeaders": {0x01, 0x10, 0x00, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := quic.DialAddr(ctx, l.conn.LocalAddr().String(), h3ClientTLS(), &quic.Config{})
			require.NoError(t, err)
			defer conn.CloseWithError(0, "")
			str, err := conn.OpenStreamSync(ctx)
			require.NoError(t, err)
			_, err = str.Write(sent)
			require.NoError(t, err)

			start := time.Now()
			_ = str.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err = str.Read(make([]byte, 1))
			var streamErr *quic.StreamError
			if assert.ErrorAs(t, err, &streamErr) {
				assert.Equal(t, quic.StreamErrorCode(http3.ErrCodeRequestIncomplete), streamErr.ErrorCode)
			}
			assert.Less(t, time.Since(start), 3*time.Second)
		})
	}
}

// The header deadline is lifted once the handler runs: a request body may
// follow its header later than handshakeTimeout.
func TestH3HeaderDeadlineLifted(t *testing.T) {
	shortHandshakeTimeout(t, 300*time.Millisecond)
	l := listenTestH3(t)

	transport := &http3.Transport{TLSClientConfig: h3ClientTLS()}
	defer transport.Close()
	body, bodyWriter := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, "https://"+l.conn.LocalAddr().String()+"/", body)
	require.NoError(t, err)

	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := transport.RoundTrip(req)
		if err != nil {
			done <- result{err: err}
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			done <- result{err: errors.New(resp.Status)}
			return
		}
		b, err := io.ReadAll(resp.Body)
		done <- result{body: b, err: err}
	}()

	time.Sleep(time.Second)
	_, err = bodyWriter.Write([]byte("hello"))
	require.NoError(t, err)
	require.NoError(t, bodyWriter.Close())
	select {
	case res := <-done:
		require.NoError(t, res.err)
		assert.True(t, bytes.Equal([]byte("hello"), res.body))
	case <-time.After(10 * time.Second):
		t.Fatal("no response")
	}
}
