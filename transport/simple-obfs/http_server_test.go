package obfs

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPObfsServerFirstPayload(t *testing.T) {
	for _, size := range []int{0, 1, 16 * 1024, maxHTTPObfsBody} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			payload := make([]byte, size)
			_, _ = rand.Read(payload)
			next := []byte("second write")
			go func() {
				client := NewHTTPObfs(clientConn, "example.com", "80")
				if size > 0 {
					_, _ = client.Write(payload)
				} else {
					_, _ = client.Write(next)
				}
				if size > 0 {
					_, _ = client.Write(next)
				}
			}()

			server := NewHTTPObfsServer(serverConn)
			want := next
			if size > 0 {
				want = append(append([]byte{}, payload...), next...)
			}
			got := make([]byte, len(want))
			_, err := io.ReadFull(server, got)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(want, got))
		})
	}
}

func TestHTTPObfsServerBodyTooLarge(t *testing.T) {
	for _, declared := range []bool{true, false} {
		t.Run(fmt.Sprint("content-length=", declared), func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			body := bytes.Repeat([]byte{'a'}, maxHTTPObfsBody+1)
			go func() {
				header := "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
				if declared {
					header += fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
					_, _ = clientConn.Write([]byte(header))
					return // the server must refuse on the header alone
				}
				header += "Transfer-Encoding: chunked\r\n\r\n"
				_, _ = clientConn.Write([]byte(header))
				_, _ = fmt.Fprintf(clientConn, "%x\r\n", len(body))
				_, _ = clientConn.Write(body)
				_, _ = clientConn.Write([]byte("\r\n0\r\n\r\n"))
			}()

			server := NewHTTPObfsServer(serverConn)
			_, err := server.Read(make([]byte, 1024))
			assert.ErrorIs(t, err, errHTTPObfsBodyTooLarge)
		})
	}
}
