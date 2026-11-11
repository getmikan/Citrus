package session

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/util"
)

// MaxServerStreams caps the streams one client session may have open on a
// server. Every stream costs a goroutine, which first waits for the stream's
// destination, so without a cap one authenticated client could open streams
// until the process runs out of memory. A SYN beyond it is answered with a
// FIN. Clients open one stream per proxied connection, and reference clients
// keep one stream per session, so 1024 is far above real use. A variable only
// so that tests can lower it.
var MaxServerStreams = 1024

type Session struct {
	conn     net.Conn
	connLock sync.Mutex

	streams    map[uint32]*Stream
	streamId   atomic.Uint32
	streamLock sync.RWMutex

	dieOnce sync.Once
	die     chan struct{}
	dieHook func()

	// data frames queued on the streams and not read yet (see recv.go)
	recvQueued atomic.Int64
	recvSpace  chan struct{}

	synDone     func()
	synDoneLock sync.Mutex

	// pool
	seq       uint64
	idleSince time.Time
	padding   *atomic.Pointer[padding.PaddingFactory]

	// peerVersion is written by recvLoop when the peer's settings arrive and
	// read by OpenStream and the handshake reports on other goroutines.
	peerVersion atomic.Uint32

	// client
	isClient       bool
	sendPadding    bool
	buffering      bool
	buffer         []byte
	pktCounter     atomic.Uint32
	clientMetadata string

	// server
	onNewStream func(stream *Stream)
}

func NewClientSession(conn net.Conn, _padding *atomic.Pointer[padding.PaddingFactory], clientMetadata string) *Session {
	s := &Session{
		conn:           conn,
		isClient:       true,
		sendPadding:    true,
		padding:        _padding,
		clientMetadata: clientMetadata,
	}
	s.die = make(chan struct{})
	s.recvSpace = make(chan struct{}, 1)
	s.streams = make(map[uint32]*Stream)
	return s
}

func NewServerSession(conn net.Conn, onNewStream func(stream *Stream), _padding *atomic.Pointer[padding.PaddingFactory]) *Session {
	s := &Session{
		conn:        conn,
		onNewStream: onNewStream,
		padding:     _padding,
	}
	s.die = make(chan struct{})
	s.recvSpace = make(chan struct{}, 1)
	s.streams = make(map[uint32]*Stream)
	return s
}

func (s *Session) Run() {
	if !s.isClient {
		// a server session's goroutine waits here for its next frame for as
		// long as the session lives: keep the frames under it small (see
		// recvLoop)
		s.recvLoop()
		return
	}
	s.runClient()
}

//go:noinline
func (s *Session) runClient() {
	settings := util.StringMap{
		"v":           "2",
		"client":      s.clientMetadata,
		"padding-md5": s.padding.Load().Md5,
	}
	f := newFrame(cmdSettings, 0)
	f.data = settings.ToBytes()
	s.buffering = true
	s.writeControlFrame(f)

	go s.recvLoop()
}

// IsClosed does a safe check to see if we have shutdown
func (s *Session) IsClosed() bool {
	select {
	case <-s.die:
		return true
	default:
		return false
	}
}

// Close is used to close the session and all streams.
func (s *Session) Close() error {
	var once bool
	s.dieOnce.Do(func() {
		_ = s.conn.SetDeadline(time.Now())
		close(s.die)
		once = true
	})
	if once {
		if s.dieHook != nil {
			s.dieHook()
			s.dieHook = nil
		}
		s.streamLock.Lock()
		for _, stream := range s.streams {
			stream.closeLocally()
		}
		s.streams = make(map[uint32]*Stream)
		s.streamLock.Unlock()
		return s.conn.Close()
	} else {
		return io.ErrClosedPipe
	}
}

// OpenStream is used to create a new stream for CLIENT. dieHook, if not nil,
// runs once when the stream dies; it is installed before the stream becomes
// visible to the session, which may close it from recvLoop at any time.
func (s *Session) OpenStream(dieHook func()) (*Stream, error) {
	if s.IsClosed() {
		return nil, io.ErrClosedPipe
	}

	sid := s.streamId.Add(1)
	stream := newStream(sid, s)
	stream.dieHook = dieHook

	if sid >= 2 && s.peerVersion.Load() >= 2 {
		s.synDoneLock.Lock()
		if s.synDone != nil {
			s.synDone()
		}
		s.synDone = util.NewDeadlineWatcher(time.Second*3, func() {
			s.Close()
		})
		s.synDoneLock.Unlock()
	}

	if _, err := s.writeControlFrame(newFrame(cmdSYN, sid)); err != nil {
		return nil, err
	}

	s.connLock.Lock()
	s.buffering = false // proxy Write it's SocksAddr to flush the buffer
	s.connLock.Unlock()

	s.streamLock.Lock()
	defer s.streamLock.Unlock()
	select {
	case <-s.die:
		return nil, io.ErrClosedPipe
	default:
		s.streams[sid] = stream
		return stream, nil
	}
}

func (s *Session) recvLoop() error {
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("[BUG] %v %s", r, string(debug.Stack()))
		}
	}()
	defer s.Close()

	var receivedSettingsFromClient bool
	var hdr rawHeader

	for {
		if s.IsClosed() {
			return io.ErrClosedPipe
		}
		// read header first
		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			return err
		}
		if done, err := s.handleFrame(hdr, &receivedSettingsFromClient); done {
			return err
		}
	}
}

// handleFrame handles a frame whose header recvLoop read, and reports whether
// the session ends, with the error to end it with.
//
// It is a function of its own so that its frame (over 1 KiB) is not on the
// stack while recvLoop waits for the next frame, which is where a session
// spends its life: the runtime shrinks a goroutine stack at GC only when
// less than a quarter of it is in use, and a large frame there keeps an idle
// session's goroutine at 16 KiB instead of 8 KiB.
//
//go:noinline
func (s *Session) handleFrame(hdr rawHeader, receivedSettingsFromClient *bool) (bool, error) {
	sid := hdr.StreamID()
	switch hdr.Cmd() {
	case cmdPSH:
		if hdr.Length() > 0 {
			buffer := buf.NewSize(int(hdr.Length()))
			if _, err := buffer.ReadFullFrom(s.conn, int(hdr.Length())); err != nil {
				buffer.Release()
				return true, err
			}
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if !ok {
				buffer.Release()
				break
			}
			stream.pushRecv(buffer)
			if err := s.waitRecvBudget(); err != nil {
				return true, err
			}
		}
	case cmdSYN: // should be server only
		if !s.isClient && !*receivedSettingsFromClient {
			f := newFrame(cmdAlert, 0)
			f.data = []byte("client did not send its settings")
			s.writeControlFrame(f)
			return true, nil
		}
		s.streamLock.Lock()
		_, exists := s.streams[sid]
		refuse := !exists && len(s.streams) >= MaxServerStreams
		if !exists && !refuse {
			stream := newStream(sid, s)
			s.streams[sid] = stream
			go func() {
				if s.onNewStream != nil {
					s.onNewStream(stream)
				} else {
					stream.Close()
				}
			}()
		}
		s.streamLock.Unlock()
		if refuse {
			// too many open streams: refuse this one without
			// allocating anything for it, as a failed handshake (v2
			// clients wait for a SYNACK) followed by a FIN
			if s.peerVersion.Load() >= 2 {
				f := newFrame(cmdSYNACK, sid)
				f.data = []byte("too many streams")
				if _, err := s.writeControlFrame(f); err != nil {
					return true, err
				}
			}
			if _, err := s.writeControlFrame(newFrame(cmdFIN, sid)); err != nil {
				return true, err
			}
		}
	case cmdSYNACK: // should be client only
		s.synDoneLock.Lock()
		if s.synDone != nil {
			s.synDone()
			s.synDone = nil
		}
		s.synDoneLock.Unlock()
		if hdr.Length() > 0 {
			buffer := pool.Get(int(hdr.Length()))
			if _, err := io.ReadFull(s.conn, buffer); err != nil {
				pool.Put(buffer)
				return true, err
			}
			// report error
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if ok {
				stream.closeWithError(fmt.Errorf("remote: %s", string(buffer)))
			}
			pool.Put(buffer)
		}
	case cmdFIN:
		s.streamLock.Lock()
		stream, ok := s.streams[sid]
		delete(s.streams, sid)
		s.streamLock.Unlock()
		if ok {
			stream.closeLocally()
		}
	case cmdWaste:
		if hdr.Length() > 0 {
			buffer := pool.Get(int(hdr.Length()))
			if _, err := io.ReadFull(s.conn, buffer); err != nil {
				pool.Put(buffer)
				return true, err
			}
			pool.Put(buffer)
		}
	case cmdSettings:
		if hdr.Length() > 0 {
			buffer := pool.Get(int(hdr.Length()))
			if _, err := io.ReadFull(s.conn, buffer); err != nil {
				pool.Put(buffer)
				return true, err
			}
			if !s.isClient {
				*receivedSettingsFromClient = true
				m := util.StringMapFromBytes(buffer)
				paddingF := s.padding.Load()
				if m["padding-md5"] != paddingF.Md5 {
					f := newFrame(cmdUpdatePaddingScheme, 0)
					f.data = paddingF.RawScheme
					_, err := s.writeControlFrame(f)
					if err != nil {
						pool.Put(buffer)
						return true, err
					}
				}
				// check client's version
				if v, ok := parsePeerVersion(m["v"]); ok && v >= 2 {
					s.peerVersion.Store(v)
					// send cmdServerSettings
					f := newFrame(cmdServerSettings, 0)
					f.data = util.StringMap{
						"v": "2",
					}.ToBytes()
					_, err := s.writeControlFrame(f)
					if err != nil {
						pool.Put(buffer)
						return true, err
					}
				}
			}
			pool.Put(buffer)
		}
	case cmdAlert:
		if hdr.Length() > 0 {
			buffer := pool.Get(int(hdr.Length()))
			if _, err := io.ReadFull(s.conn, buffer); err != nil {
				pool.Put(buffer)
				return true, err
			}
			if s.isClient {
				log.Errorln("[Alert from server] %s", string(buffer))
			}
			pool.Put(buffer)
			return true, nil
		}
	case cmdUpdatePaddingScheme:
		if hdr.Length() > 0 {
			// `rawScheme` Do not use buffer to prevent subsequent misuse
			rawScheme := make([]byte, int(hdr.Length()))
			if _, err := io.ReadFull(s.conn, rawScheme); err != nil {
				return true, err
			}
			if s.isClient {
				if padding.UpdatePaddingScheme(rawScheme, s.padding) {
					log.Debugln("[Update padding succeed] %x\n", md5.Sum(rawScheme))
				} else {
					log.Warnln("[Update padding failed] %x\n", md5.Sum(rawScheme))
				}
			}
		}
	case cmdHeartRequest:
		if _, err := s.writeControlFrame(newFrame(cmdHeartResponse, sid)); err != nil {
			return true, err
		}
	case cmdHeartResponse:
		// Active keepalive checking is not implemented yet
		break
	case cmdServerSettings:
		if hdr.Length() > 0 {
			buffer := pool.Get(int(hdr.Length()))
			if _, err := io.ReadFull(s.conn, buffer); err != nil {
				pool.Put(buffer)
				return true, err
			}
			if s.isClient {
				// check server's version
				m := util.StringMapFromBytes(buffer)
				if v, ok := parsePeerVersion(m["v"]); ok {
					s.peerVersion.Store(v)
				}
			}
			pool.Put(buffer)
		}
	default:
		// I don't know what command it is (can't have data)
	}
	return false, nil
}

func (s *Session) streamClosed(sid uint32) error {
	if s.IsClosed() {
		return io.ErrClosedPipe
	}
	_, err := s.writeControlFrame(newFrame(cmdFIN, sid))
	s.streamLock.Lock()
	delete(s.streams, sid)
	s.streamLock.Unlock()
	return err
}

// maxFrameDataLen is the maximum payload bytes per data frame. The wire
// format encodes payload length as a uint16, so a single frame cannot
// carry more than 65535 bytes. writeDataFrame splits larger writes into
// multiple frames and sends the whole frame sequence in one writeConn call.
// That keeps one Stream.Write contiguous relative to other stream/control
// frame writes.
const maxFrameDataLen = 0xFFFF

func (s *Session) writeDataFrame(sid uint32, data []byte) (int, error) {
	dataLen := len(data)
	if dataLen == 0 {
		return 0, nil
	}
	if dataLen <= maxFrameDataLen {
		buffer := buf.NewSize(dataLen + headerOverHeadSize)
		buffer.WriteByte(cmdPSH)
		binary.BigEndian.PutUint32(buffer.Extend(4), sid)
		binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
		buffer.Write(data)
		_, err := s.writeConn(buffer.Bytes())
		buffer.Release()
		if err != nil {
			return 0, err
		}
		return dataLen, nil
	}

	frameCount := (dataLen + maxFrameDataLen - 1) / maxFrameDataLen
	buffer := buf.NewSize(dataLen + frameCount*headerOverHeadSize)
	defer buffer.Release()

	for written := 0; written < dataLen; {
		chunk := dataLen - written
		if chunk > maxFrameDataLen {
			chunk = maxFrameDataLen
		}
		buffer.WriteByte(cmdPSH)
		binary.BigEndian.PutUint32(buffer.Extend(4), sid)
		binary.BigEndian.PutUint16(buffer.Extend(2), uint16(chunk))
		buffer.Write(data[written : written+chunk])
		written += chunk
	}

	if _, err := s.writeConn(buffer.Bytes()); err != nil {
		return 0, err
	}
	return dataLen, nil
}

// writeDataBuffer is writeDataFrame for a buffer that the caller hands over:
// with room for the header in front of the data (Stream.FrontHeadroom), the
// frame is built in place instead of being copied into a new buffer. The
// buffer is released in every case.
func (s *Session) writeDataBuffer(sid uint32, buffer *buf.Buffer) error {
	dataLen := buffer.Len()
	if dataLen == 0 {
		buffer.Release()
		return nil
	}
	if dataLen > maxFrameDataLen || buffer.Start() < headerOverHeadSize {
		_, err := s.writeDataFrame(sid, buffer.Bytes())
		buffer.Release()
		return err
	}
	header := buffer.ExtendHeader(headerOverHeadSize)
	header[0] = cmdPSH
	binary.BigEndian.PutUint32(header[1:5], sid)
	binary.BigEndian.PutUint16(header[5:7], uint16(dataLen))
	_, err := s.writeConn(buffer.Bytes())
	buffer.Release()
	return err
}

func (s *Session) writeControlFrame(frame frame) (int, error) {
	dataLen := len(frame.data)

	buffer := buf.NewSize(dataLen + headerOverHeadSize)
	buffer.WriteByte(frame.cmd)
	binary.BigEndian.PutUint32(buffer.Extend(4), frame.sid)
	binary.BigEndian.PutUint16(buffer.Extend(2), uint16(dataLen))
	buffer.Write(frame.data)

	s.conn.SetWriteDeadline(time.Now().Add(time.Second * 5))

	_, err := s.writeConn(buffer.Bytes())
	buffer.Release()
	if err != nil {
		s.Close()
		return 0, err
	}

	s.conn.SetWriteDeadline(time.Time{})

	return dataLen, nil
}

func (s *Session) writeConn(b []byte) (n int, err error) {
	s.connLock.Lock()
	defer s.connLock.Unlock()

	if s.buffering {
		s.buffer = append(s.buffer, b...)
		return len(b), nil
	} else if len(s.buffer) > 0 {
		b = append(s.buffer, b...)
		s.buffer = nil
	}

	// calulate & send padding
	if s.sendPadding {
		pkt := s.pktCounter.Add(1)
		paddingF := s.padding.Load()
		if pkt < paddingF.Stop {
			pktSizes := paddingF.GenerateRecordPayloadSizes(pkt)
			for _, l := range pktSizes {
				remainPayloadLen := len(b)
				if l == padding.CheckMark {
					if remainPayloadLen == 0 {
						break
					} else {
						continue
					}
				}
				if remainPayloadLen > l { // this packet is all payload
					_, err = s.conn.Write(b[:l])
					if err != nil {
						return 0, err
					}
					n += l
					b = b[l:]
				} else if remainPayloadLen > 0 { // this packet contains padding and the last part of payload
					paddingLen := l - remainPayloadLen - headerOverHeadSize
					if paddingLen > 0 {
						padding := make([]byte, headerOverHeadSize+paddingLen)
						padding[0] = cmdWaste
						binary.BigEndian.PutUint32(padding[1:5], 0)
						binary.BigEndian.PutUint16(padding[5:7], uint16(paddingLen))
						b = append(b, padding...)
					}
					_, err = s.conn.Write(b)
					if err != nil {
						return 0, err
					}
					n += remainPayloadLen
					b = nil
				} else { // this packet is all padding
					padding := make([]byte, headerOverHeadSize+l)
					padding[0] = cmdWaste
					binary.BigEndian.PutUint32(padding[1:5], 0)
					binary.BigEndian.PutUint16(padding[5:7], uint16(l))
					_, err = s.conn.Write(padding)
					if err != nil {
						return 0, err
					}
					b = nil
				}
			}
			// maybe still remain payload to write
			if len(b) == 0 {
				return
			} else {
				n2, err := s.conn.Write(b)
				return n + n2, err
			}
		} else {
			s.sendPadding = false
		}
	}

	return s.conn.Write(b)
}

// parsePeerVersion reads the "v" field of the peer's settings. It comes off the
// wire, so a negative or oversized value is rejected rather than wrapped into a
// uint32 (a "-1" would otherwise read as a huge version and turn on v2 features).
func parsePeerVersion(s string) (uint32, bool) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}
