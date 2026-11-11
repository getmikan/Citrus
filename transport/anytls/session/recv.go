package session

import (
	"io"
	"os"
	"runtime"

	"github.com/metacubex/mihomo/common/buf"

	N "github.com/metacubex/sing/common/network"
)

// recvBudget bounds the bytes of data frames that a session holds for
// streams whose readers have not taken them yet. recvLoop queues every data
// frame on its stream and goes on with the next frame; past the budget it
// waits for the readers before it reads more from the connection, so a
// reader that does not keep up slows the session down as TCP would, with a
// bounded amount of memory.
//
// The streams used to get their data through a synchronous pipe: recvLoop
// waited for the reader of every frame, one goroutine switch each way, and
// the reader copied the frame out of recvLoop's buffer. Now recvLoop decrypts
// the next frames while the readers write the previous ones, and a reader
// that waits for buffers (N.ReadWaiter, the relay) takes the frame's own
// buffer without a copy. A variable only so that tests can lower it.
var recvBudget int64 = 512 * 1024

// pushRecv queues a data frame for the reader; the stream owns buffer from
// here on. A stream that is closed for reading drops it.
func (s *Stream) pushRecv(buffer *buf.Buffer) {
	s.recvLock.Lock()
	if s.recvClosed {
		s.recvLock.Unlock()
		buffer.Release()
		return
	}
	s.recvBufs = append(s.recvBufs, buffer)
	s.sess.recvQueued.Add(int64(buffer.Len()))
	waiting := s.recvWaiting
	s.recvWaiting = false
	s.recvLock.Unlock()
	if waiting {
		// The reader waits: wake it, and give it this processor, where the
		// runtime has queued it to run next. Without the yield recvLoop
		// keeps the processor, and the reader is taken over by another
		// thread that has to be woken up for every frame: a single upload
		// ran about 7% slower than with the synchronous pipe before
		// (1583 against 1696 MB/s), and 1680 with the yield. A reader that
		// does not wait (it is busy writing) is not woken at all.
		s.signalReadable()
		runtime.Gosched()
	}
}

func (s *Stream) signalReadable() {
	select {
	case s.readable <- struct{}{}:
	default:
	}
}

// closeRecv ends the queue: no frame is queued after it. drop releases the
// frames not read yet (the stream is closed locally, nobody reads them);
// otherwise they are still read, and the reads end after them (the peer
// closed the stream after sending them).
func (s *Stream) closeRecv(drop bool) {
	var dropped int
	s.recvLock.Lock()
	s.recvClosed = true
	if drop {
		for i := s.recvHead; i < len(s.recvBufs); i++ {
			dropped += s.recvBufs[i].Len()
			s.recvBufs[i].Release()
		}
		s.recvBufs, s.recvHead = nil, 0
	}
	dropped = s.takenLocked(dropped)
	s.recvLock.Unlock()
	s.sess.recvTaken(dropped)
	s.signalReadable()
}

// detachRecv takes the frames still queued on a stream whose queue has ended
// out of the session's budget. They stay queued for a reader that is still
// there, and are garbage once the stream is; the peer sends no more frames
// on the stream, so it holds no more than it had queued.
func (s *Stream) detachRecv() {
	var queued int
	s.recvLock.Lock()
	if s.recvClosed && !s.recvDetached {
		for i := s.recvHead; i < len(s.recvBufs); i++ {
			queued += s.recvBufs[i].Len()
		}
		s.recvDetached = true
	}
	s.recvLock.Unlock()
	s.sess.recvTaken(queued)
}

// takenLocked returns how much of n bytes leaving the queue the session
// gets back: none once the queue is detached from its budget.
func (s *Stream) takenLocked(n int) int {
	if s.recvDetached {
		return 0
	}
	return n
}

// popRecvLocked removes the head frame, which the caller has taken.
func (s *Stream) popRecvLocked() {
	s.recvBufs[s.recvHead] = nil
	s.recvHead++
	if s.recvHead == len(s.recvBufs) {
		s.recvBufs, s.recvHead = s.recvBufs[:0], 0
	}
}

// waitRecv waits until a frame is queued or the queue ends; it returns with
// recvLock held when a frame is there.
func (s *Stream) waitRecv() error {
	for {
		s.recvLock.Lock()
		if s.recvHead < len(s.recvBufs) {
			return nil
		}
		closed := s.recvClosed
		// pushRecv wakes the reader only when it waits
		s.recvWaiting = !closed
		s.recvLock.Unlock()
		if closed {
			if err := s.closeErr(); err != nil {
				return err
			}
			return io.ErrClosedPipe
		}
		select {
		case <-s.readable:
		case <-s.readDeadline.Wait():
			return os.ErrDeadlineExceeded
		}
	}
}

// Read implements net.Conn
func (s *Stream) Read(b []byte) (int, error) {
	if err := s.waitRecv(); err != nil {
		return 0, err
	}
	head := s.recvBufs[s.recvHead]
	n := copy(b, head.Bytes())
	head.Advance(n)
	if head.IsEmpty() {
		head.Release()
		s.popRecvLocked()
	}
	taken := s.takenLocked(n)
	s.recvLock.Unlock()
	s.sess.recvTaken(taken)
	return n, nil
}

// InitializeReadWaiter implements N.ReadWaiter.
func (s *Stream) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	s.recvLock.Lock()
	s.readOptions = options
	s.recvLock.Unlock()
	return false
}

// WaitReadBuffer implements N.ReadWaiter: it hands over the next frame's
// buffer, copied only when the destination needs headroom around the data.
func (s *Stream) WaitReadBuffer() (*buf.Buffer, error) {
	if err := s.waitRecv(); err != nil {
		return nil, err
	}
	buffer := s.recvBufs[s.recvHead]
	s.popRecvLocked()
	options := s.readOptions
	taken := s.takenLocked(buffer.Len())
	s.recvLock.Unlock()
	s.sess.recvTaken(taken)
	return withHeadroom(buffer, options), nil
}

// WaitReadBuffers hands over every queued frame at once, so that the relay
// writes them in one writev(2). The slice is reused by the next call.
func (s *Stream) WaitReadBuffers() ([]*buf.Buffer, error) {
	if err := s.waitRecv(); err != nil {
		return nil, err
	}
	batch := append(s.readBatch[:0], s.recvBufs[s.recvHead:]...)
	clear(s.recvBufs)
	s.recvBufs, s.recvHead = s.recvBufs[:0], 0
	options := s.readOptions
	detached := s.recvDetached
	s.recvLock.Unlock()
	s.readBatch = batch
	var n int
	for i, buffer := range batch {
		n += buffer.Len()
		batch[i] = withHeadroom(buffer, options)
	}
	if !detached {
		s.sess.recvTaken(n)
	}
	return batch, nil
}

// withHeadroom returns buffer, or a copy of it with the headroom that options
// ask for when buffer lacks it.
func withHeadroom(buffer *buf.Buffer, options N.ReadWaitOptions) *buf.Buffer {
	if options.FrontHeadroom <= buffer.Start() && options.RearHeadroom <= buffer.FreeLen() {
		return buffer
	}
	n := buffer.Len()
	withRoom := buf.NewSize(options.FrontHeadroom + n + options.RearHeadroom)
	withRoom.Resize(options.FrontHeadroom, 0)
	_, _ = withRoom.Write(buffer.Bytes())
	buffer.Release()
	return withRoom
}

// recvTaken accounts for n bytes that left the queues of the session, and
// wakes recvLoop when they bring the session back within its budget.
func (s *Session) recvTaken(n int) {
	if n == 0 {
		return
	}
	left := s.recvQueued.Add(-int64(n))
	if left <= recvBudget && left+int64(n) > recvBudget {
		select {
		case s.recvSpace <- struct{}{}:
		default:
		}
	}
}

// waitRecvBudget blocks recvLoop while the session holds more than its budget.
func (s *Session) waitRecvBudget() error {
	for s.recvQueued.Load() > recvBudget {
		select {
		case <-s.recvSpace:
		case <-s.die:
			return io.ErrClosedPipe
		}
	}
	return nil
}
