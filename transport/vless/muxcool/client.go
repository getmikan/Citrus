// Package muxcool implements the TCP client side of the Mux.Cool wire format.
// UDP uses the existing XUDP implementation in the VLESS adapter.
package muxcool

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
)

const (
	maxStreams  = 8
	maxSessions = 4
	chunkSize   = 8 * 1024
)

type Client struct {
	dial     func(context.Context) (net.Conn, error)
	mu       sync.Mutex
	sessions []*session
	dialing  int
	closed   bool
	notify   chan struct{}
}

func NewClient(dial func(context.Context) (net.Conn, error)) *Client {
	return &Client{dial: dial, notify: make(chan struct{})}
}
func (c *Client) wakeLocked() { close(c.notify); c.notify = make(chan struct{}) }
func (c *Client) DialContext(ctx context.Context, addr string) (net.Conn, error) {
	target, err := encodeTarget(addr)
	if err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, net.ErrClosed
		}
		live := c.sessions[:0]
		for _, s := range c.sessions {
			select {
			case <-s.done:
			default:
				live = append(live, s)
			}
		}
		c.sessions = live
		for _, s := range c.sessions {
			if len(s.streams) >= maxStreams || s.nextID == 65535 {
				continue
			}
			s.nextID++
			st := &stream{session: s, id: s.nextID, data: make(chan []byte, 16), done: make(chan struct{}), readDeadline: deadline.MakePipeDeadline(), writeDeadline: deadline.MakePipeDeadline()}
			s.streams[st.id] = st
			c.mu.Unlock()
			if err := s.send(ctx, frame(st.id, 1, 0, target, nil), &st.writeDeadline); err != nil {
				st.finish(err)
				return nil, err
			}
			return st, nil
		}
		if len(c.sessions)+c.dialing < maxSessions {
			c.dialing++
			c.mu.Unlock()
			conn, err := c.dial(ctx)
			c.mu.Lock()
			c.dialing--
			closed := c.closed
			if err == nil && !closed {
				s := &session{client: c, conn: conn, streams: make(map[uint16]*stream), done: make(chan struct{}), writes: make(chan writeRequest, 16)}
				c.sessions = append(c.sessions, s)
				go s.readLoop()
				go s.writeLoop()
			}
			c.wakeLocked()
			c.mu.Unlock()
			if closed {
				if conn != nil {
					_ = conn.Close()
				}
				return nil, net.ErrClosed
			}
			if err != nil {
				return nil, err
			}
			continue
		}
		notify := c.notify
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-notify:
		}
	}
}
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	sessions := append([]*session(nil), c.sessions...)
	c.wakeLocked()
	c.mu.Unlock()
	for _, s := range sessions {
		s.fail(net.ErrClosed)
	}
	return nil
}

type writeRequest struct {
	data []byte
	done chan error
}
type session struct {
	client  *Client
	conn    net.Conn
	streams map[uint16]*stream // guarded by client.mu
	nextID  uint16
	writes  chan writeRequest
	done    chan struct{}
	once    sync.Once
}

func (s *session) send(ctx context.Context, data []byte, d *deadline.PipeDeadline) error {
	req := writeRequest{data: data, done: make(chan error, 1)}
	select {
	case s.writes <- req:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return net.ErrClosed
	case <-d.Wait():
		return os.ErrDeadlineExceeded
	}
	select {
	case err := <-req.done:
		return err
	case <-ctx.Done():
		s.fail(ctx.Err())
		return ctx.Err()
	case <-s.done:
		return net.ErrClosed
	case <-d.Wait():
		s.fail(os.ErrDeadlineExceeded)
		return os.ErrDeadlineExceeded
	}
}
func (s *session) writeLoop() {
	for {
		select {
		case <-s.done:
			return
		case req := <-s.writes:
			p := req.data
			var err error
			for len(p) > 0 {
				var n int
				n, err = s.conn.Write(p)
				if n > 0 {
					p = p[n:]
				}
				if err != nil {
					break
				}
				if n == 0 {
					err = io.ErrShortWrite
					break
				}
			}
			req.done <- err
			if err != nil {
				s.fail(err)
				return
			}
		}
	}
}
func (s *session) readLoop() {
	for {
		var length [2]byte
		if _, err := io.ReadFull(s.conn, length[:]); err != nil {
			s.fail(err)
			return
		}
		n := int(binary.BigEndian.Uint16(length[:]))
		if n < 4 || n > 512 {
			s.fail(errors.New("invalid Mux.Cool metadata length"))
			return
		}
		meta := make([]byte, n)
		if _, err := io.ReadFull(s.conn, meta); err != nil {
			s.fail(err)
			return
		}
		id, status, options := binary.BigEndian.Uint16(meta), meta[2], meta[3]
		var data []byte
		if options&1 != 0 {
			if _, err := io.ReadFull(s.conn, length[:]); err != nil {
				s.fail(err)
				return
			}
			data = make([]byte, int(binary.BigEndian.Uint16(length[:])))
			if _, err := io.ReadFull(s.conn, data); err != nil {
				s.fail(err)
				return
			}
		}
		if status == 4 {
			continue
		}
		if status != 2 && status != 3 {
			s.fail(fmt.Errorf("unexpected Mux.Cool status %d", status))
			return
		}
		s.client.mu.Lock()
		st := s.streams[id]
		s.client.mu.Unlock()
		if st == nil {
			continue
		}
		if len(data) > 0 {
			select {
			case st.data <- data:
			case <-st.done:
			case <-s.done:
				return
			}
		}
		if status == 3 {
			if options&2 != 0 {
				st.finish(errors.New("Mux.Cool peer rejected stream"))
			} else {
				st.finish(io.EOF)
			}
		}
	}
}
func (s *session) fail(err error) {
	s.once.Do(func() {
		close(s.done)
		s.client.mu.Lock()
		streams := make([]*stream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.client.wakeLocked()
		s.client.mu.Unlock()
		for _, st := range streams {
			st.finish(err)
		}
		go func() { _ = s.conn.Close() }()
	})
}

type stream struct {
	session                     *session
	id                          uint16
	data                        chan []byte
	done                        chan struct{}
	readBuf                     []byte
	readMu                      sync.Mutex
	readDeadline, writeDeadline deadline.PipeDeadline
	writeMu                     sync.Mutex
	err                         error // set before done is closed
	once, closeOnce             sync.Once
}

func (s *stream) finish(err error) {
	s.once.Do(func() {
		s.err = err
		close(s.done)
		s.session.client.mu.Lock()
		delete(s.session.streams, s.id)
		s.session.client.wakeLocked()
		exhausted := s.session.nextID == 65535 && len(s.session.streams) == 0
		s.session.client.mu.Unlock()
		if exhausted {
			go s.session.fail(io.EOF)
		}
	})
}
func (s *stream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if len(s.readBuf) == 0 {
		// Deliver queued payload before reporting the peer's End frame.
		select {
		case s.readBuf = <-s.data:
		default:
		}
		if len(s.readBuf) == 0 {
			select {
			case s.readBuf = <-s.data:
			case <-s.readDeadline.Wait():
				return 0, os.ErrDeadlineExceeded
			case <-s.done:
				select {
				case s.readBuf = <-s.data:
				default:
					return 0, s.err
				}
			}
		}
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}
func (s *stream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		select {
		case <-s.done:
			return total, net.ErrClosed
		default:
		}
		n := min(len(p), chunkSize)
		if err := s.session.send(context.Background(), frame(s.id, 2, 1, nil, p[:n]), &s.writeDeadline); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func (s *stream) Close() error {
	s.closeOnce.Do(func() {
		select {
		case <-s.done:
			return
		default:
		}
		s.finish(net.ErrClosed)
		d := deadline.MakePipeDeadline()
		d.Set(time.Now().Add(time.Second))
		defer d.Set(time.Time{})
		_ = s.session.send(context.Background(), frame(s.id, 3, 0, nil, nil), &d)
		s.readDeadline.Set(time.Time{})
		s.writeDeadline.Set(time.Time{})
	})
	return nil
}
func (s *stream) LocalAddr() net.Addr  { return s.session.conn.LocalAddr() }
func (s *stream) RemoteAddr() net.Addr { return s.session.conn.RemoteAddr() }
func (s *stream) SetDeadline(t time.Time) error {
	s.readDeadline.Set(t)
	s.writeDeadline.Set(t)
	return nil
}
func (s *stream) SetReadDeadline(t time.Time) error  { s.readDeadline.Set(t); return nil }
func (s *stream) SetWriteDeadline(t time.Time) error { s.writeDeadline.Set(t); return nil }

func frame(id uint16, status, options byte, target, payload []byte) []byte {
	n := 4 + len(target)
	size := 2 + n
	if options&1 != 0 {
		size += 2 + len(payload)
	}
	b := make([]byte, size)
	binary.BigEndian.PutUint16(b, uint16(n))
	binary.BigEndian.PutUint16(b[2:], id)
	b[4] = status
	b[5] = options
	copy(b[6:], target)
	if options&1 != 0 {
		binary.BigEndian.PutUint16(b[2+n:], uint16(len(payload)))
		copy(b[4+n:], payload)
	}
	return b
}
func encodeTarget(addr string) ([]byte, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return nil, fmt.Errorf("invalid Mux.Cool destination port")
	}
	b := []byte{1, byte(p >> 8), byte(p)}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return append(append(b, 1), v4...), nil
		}
		return append(append(b, 3), ip.To16()...), nil
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, errors.New("invalid Mux.Cool destination host")
	}
	return append(append(b, 2, byte(len(host))), []byte(host)...), nil
}
