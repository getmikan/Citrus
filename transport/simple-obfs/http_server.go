package obfs

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/randv2"
)

// maxHTTPObfsBody bounds the body of the obfs request. A client puts the data
// of its first write there, which is one relay buffer at most.
const maxHTTPObfsBody = 64 * 1024

var errHTTPObfsBodyTooLarge = errors.New("simple-obfs: http request body too large")

type HTTPObfsServer struct {
	net.Conn
	buf           []byte
	bio           *bufio.Reader
	offset        int
	firstRequest  bool
	firstResponse bool
}

func (hos *HTTPObfsServer) Upstream() any {
	return hos.Conn
}

func (hos *HTTPObfsServer) Read(b []byte) (int, error) {
	if hos.buf != nil {
		n := copy(b, hos.buf[hos.offset:])
		hos.offset += n
		if hos.offset == len(hos.buf) {
			hos.offset = 0
			hos.buf = nil
		}
		return n, nil
	}

	if hos.firstRequest {
		bio := bufio.NewReader(hos.Conn)
		req, err := http.ReadRequest(bio)
		if err != nil {
			return 0, err
		}
		if req.Method != "GET" || req.Header.Get("Connection") != "Upgrade" {
			return 0, io.EOF
		}

		// the body carries the client's first payload; bound it before the
		// inner protocol has had a chance to check anything
		if req.ContentLength > maxHTTPObfsBody {
			return 0, errHTTPObfsBodyTooLarge
		}
		buf, err := io.ReadAll(io.LimitReader(req.Body, maxHTTPObfsBody+1))
		if err != nil {
			return 0, err
		}
		if len(buf) > maxHTTPObfsBody {
			return 0, errHTTPObfsBodyTooLarge
		}
		n := copy(b, buf)
		if n < len(buf) {
			hos.buf = buf
			hos.offset = n
		}
		req.Body.Close()
		hos.bio = bio
		hos.firstRequest = false
		return n, nil
	}

	return hos.bio.Read(b)
}

const httpResponseTemplate = "HTTP/1.1 101 Switching Protocols\r\n" +
	"Server: nginx/1.%d.%d\r\n" +
	"Date: %s\r\n" +
	"Upgrade: websocket\r\n" +
	"Connection: Upgrade\r\n" +
	"Sec-WebSocket-Accept: %s\r\n" +
	"\r\n"

var vMajor = randv2.IntN(11)
var vMinor = randv2.IntN(12)

func (hos *HTTPObfsServer) Write(b []byte) (int, error) {
	if hos.firstResponse {
		randBytes := make([]byte, 16)
		rand.Read(randBytes)
		date := time.Now().Format(time.RFC1123)
		resp := fmt.Sprintf(httpResponseTemplate, vMajor, vMinor, date, base64.URLEncoding.EncodeToString(randBytes))
		_, err := hos.Conn.Write([]byte(resp))
		if err != nil {
			return 0, err
		}
		hos.firstResponse = false
	}
	return hos.Conn.Write(b)
}

func NewHTTPObfsServer(conn net.Conn) net.Conn {
	return &HTTPObfsServer{
		Conn:          conn,
		buf:           nil,
		bio:           nil,
		offset:        0,
		firstRequest:  true,
		firstResponse: true,
	}
}
