package net

import (
	"errors"
	"io"
	"syscall"

	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	"github.com/metacubex/sing/common/network"
)

// smallReadSize is the buffer, headroom included, that the relay reads into
// while a connection looks idle: a connection that waits for its peer holds
// this much instead of a full pool buffer (buf.BufferSize, 32 KiB).
const smallReadSize = 2048

// minSmallRead keeps the small buffer usable when the destination asks for a
// large headroom.
const minSmallRead = 512

// shortReadsToShrink is how many reads in a row that the small buffer would
// have held switch a copy on full buffers back to the small one. One is not
// enough: a bulk stream of a protocol that splits its frames (Shadowsocks
// chunks, for one) alternates full and short reads, and would pay an extra
// read and write per frame.
const shortReadsToShrink = 2

// copyConn is bufio.Copy with another fallback for sources that cannot wait
// for data without a buffer.
//
// bufio.Copy ends in bufio.CopyExtendedWithPool for a source that is neither a
// socket (splice, or a read waiter that takes a buffer only once the socket
// is readable) nor a read waiter of its own, such as a TLS or REALITY
// connection. That loop takes a 32 KiB pool buffer before every read, so a
// connection whose client is silent keeps one for as long as it stays open:
// about two thirds of the live heap of an idle proxied connection.
//
// copyConn reads such a source into a small buffer while the connection looks
// idle and into full pool buffers while data keeps coming: a read that fills
// the small buffer switches to full buffers, and shortReadsToShrink reads in
// a row that return no more than the small buffer would have held switch
// back. A bulk transfer runs on full buffers as before, at the cost of one
// more read where it starts; a connection that waits after short messages
// waits on the small buffer.
//
// Everything else (cached data, splice, read waiters) is bufio.Copy's own
// code. The copy of single buffers while Vision may still replace the reader
// or the writer chooses its buffer the same way.
func copyConn(destination io.Writer, source io.Reader) (n int64, err error) {
	if source == nil {
		return 0, errors.New("nil reader")
	} else if destination == nil {
		return 0, errors.New("nil writer")
	}
	originSource := source
	var readCounters, writeCounters []network.CountFunc
	var _n int64
	var sizing readSizing
	possibly := bufio.MaxCopyExtendedOnceTimes
	for {
		source, readCounters = network.UnwrapCountReader(source, readCounters)
		destination, writeCounters = network.UnwrapCountWriter(destination, writeCounters)
		if cachedSrc, isCached := source.(network.CachedReader); isCached {
			cachedBuffer := cachedSrc.ReadCached()
			if cachedBuffer != nil {
				dataLen := cachedBuffer.Len()
				_, err = destination.Write(cachedBuffer.Bytes())
				cachedBuffer.Release()
				if err != nil {
					return
				}
				countAll(readCounters, writeCounters, dataLen)
				continue
			}
		}
		replaceableReader, isReaderPossiblyReplaceable := source.(network.ReaderPossiblyReplaceable)
		replaceableWriter, isWriterPossiblyReplaceable := destination.(network.WriterPossiblyReplaceable)
		// Same condition (and operator precedence) as bufio.Copy.
		if possibly != 0 &&
			(isReaderPossiblyReplaceable && replaceableReader.ReaderPossiblyReplaceable()) ||
			(isWriterPossiblyReplaceable && replaceableWriter.WriterPossiblyReplaceable()) {
			possibly--
			_n, err = copyOnce(destination, source, readCounters, writeCounters, &sizing)
			n += _n
			if err != nil {
				if n == _n { // first time
					err = network.ReportHandshakeFailure(originSource, err)
				}
				if errors.Is(err, io.EOF) {
					err = nil
				}
				return
			}
			continue
		}
		break
	}
	_, srcIsSyscall := source.(syscall.Conn)
	_, dstIsSyscall := destination.(syscall.Conn)
	if srcIsSyscall && dstIsSyscall {
		// Splice, or a socket read waiter when it cannot: no buffer while idle.
		_n, err = bufio.CopyWithCounters(destination, source, originSource, readCounters, writeCounters)
		n += _n
		return
	}
	_n, err = copyExtended(originSource, bufio.NewExtendedWriter(destination), bufio.NewExtendedReader(source), readCounters, writeCounters, &sizing, srcIsSyscall)
	n += _n
	return
}

// copyExtended is bufio.CopyExtended with copyAdaptive in place of
// bufio.CopyExtendedWithPool.
func copyExtended(originSource io.Reader, destination network.ExtendedWriter, source network.ExtendedReader, readCounters []network.CountFunc, writeCounters []network.CountFunc, sizing *readSizing, fromSocket bool) (n int64, err error) {
	options := network.NewReadWaitOptions(source, destination)
	if readWaiter, isReadWaiter := bufio.CreateReadWaiter(source); isReadWaiter {
		needCopy := readWaiter.InitializeReadWaiter(options)
		if !needCopy || common.LowMemory {
			return copyWait(originSource, destination, readWaiter, options, fromSocket, readCounters, writeCounters)
		}
	}
	return copyAdaptive(originSource, destination, source, options, readCounters, writeCounters, sizing)
}

// largeReadSize is the buffer, headroom included, that a copy from a socket
// reads into once a transfer runs: the largest pool buffer (buf.BufferSize is
// half of it). Every write to the destination carries twice the data: a
// Shadowsocks 2022 connection seals it as one chunk (up to 65535 bytes), a TLS
// one encrypts four records. The socket read waiter takes a buffer only once
// data is there, so an idle connection holds none of either size.
const largeReadSize = 65535

// copyWait is the read waiter loop of bufio.CopyExtended. From a socket
// (fromSocket), a read that fills the buffer switches to largeReadSize
// buffers for the rest of the copy.
func copyWait(originSource io.Reader, destination network.ExtendedWriter, source network.ReadWaiter, options network.ReadWaitOptions, fromSocket bool, readCounters []network.CountFunc, writeCounters []network.CountFunc) (n int64, err error) {
	var notFirstTime bool
	var yield relayYield
	grow := fromSocket && options.MTU == 0 && !common.LowMemory
	fullRead := buf.BufferSize - options.FrontHeadroom - options.RearHeadroom
	for {
		var buffer *buf.Buffer
		buffer, err = source.WaitReadBuffer()
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
			}
			return
		}
		dataLen := buffer.Len()
		err = destination.WriteBuffer(buffer)
		if err != nil {
			buffer.Leak()
			if !notFirstTime {
				err = network.ReportHandshakeFailure(originSource, err)
			}
			return
		}
		n += int64(dataLen)
		countAll(readCounters, writeCounters, dataLen)
		notFirstTime = true
		yield.add(dataLen)
		if grow && dataLen >= fullRead {
			grow = false
			options.MTU = largeReadSize - options.FrontHeadroom - options.RearHeadroom
			source.InitializeReadWaiter(options)
		}
	}
}

// copyAdaptive is bufio.CopyExtendedWithPool that waits on a small buffer
// while the source is idle (see copyConn).
func copyAdaptive(originSource io.Reader, destination network.ExtendedWriter, source network.ExtendedReader, options network.ReadWaitOptions, readCounters []network.CountFunc, writeCounters []network.CountFunc, sizing *readSizing) (n int64, err error) {
	small := smallReadLen(options)
	if small == 0 {
		return bufio.CopyExtendedWithPool(originSource, destination, source, readCounters, writeCounters)
	}
	var notFirstTime bool
	var yield relayYield
	writer := batchWriter(destination)
	waiter, _ := network.UnwrapReader(source).(readWaitable)
	for {
		if writer != nil && sizing.full {
			// A transfer is running: read ahead and write in batches.
			batched, handedBack, batchErr := copyBatched(destination, writer, source, options, readCounters, writeCounters, sizing, small)
			n += batched
			if !handedBack {
				return n, batchErr
			}
		}
		if waiter != nil && !sizing.full {
			// wait for data without a buffer
			if err = waiter.WaitRead(); err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}
				return
			}
		}
		buffer := sizing.newBuffer(options, small)
		err = source.ReadBuffer(buffer)
		if err != nil {
			buffer.Release()
			if errors.Is(err, io.EOF) {
				err = nil
			}
			return
		}
		dataLen := buffer.Len()
		options.PostReturn(buffer)
		err = destination.WriteBuffer(buffer)
		if err != nil {
			buffer.Leak()
			if !notFirstTime {
				err = network.ReportHandshakeFailure(originSource, err)
			}
			return
		}
		n += int64(dataLen)
		countAll(readCounters, writeCounters, dataLen)
		notFirstTime = true
		sizing.update(dataLen, small)
		yield.add(dataLen)
	}
}

// copyOnce is bufio.CopyExtendedOnce, which copies one buffer while Vision
// may still replace the reader or the writer, with the buffer choice of
// copyAdaptive: Vision pads the first packets of every connection, and a
// connection that goes quiet in that phase waits here.
func copyOnce(destination io.Writer, source io.Reader, readCounters []network.CountFunc, writeCounters []network.CountFunc, sizing *readSizing) (n int64, err error) {
	options := network.NewReadWaitOptions(source, destination)
	var buffer *buf.Buffer
	calledWaitRead := false
	if readWaiter, isReadWaiter := bufio.CreateReadWaiter(source); isReadWaiter {
		if needCopy := readWaiter.InitializeReadWaiter(options); !needCopy || common.LowMemory {
			calledWaitRead = true
			buffer, err = readWaiter.WaitReadBuffer()
		}
	}
	small := smallReadLen(options)
	if !calledWaitRead {
		buffer = sizing.newBuffer(options, small)
		err = bufio.NewExtendedReader(source).ReadBuffer(buffer)
		options.PostReturn(buffer)
	}
	if err != nil {
		if buffer != nil {
			buffer.Release()
		}
		return
	}
	dataLen := buffer.Len()
	err = bufio.NewExtendedWriter(destination).WriteBuffer(buffer)
	if err != nil {
		buffer.Release()
		return
	}
	countAll(readCounters, writeCounters, dataLen)
	n = int64(dataLen)
	sizing.update(dataLen, small)
	return
}

// readWaitable is a source that can wait for data without a buffer
// (getmikan/tls Conn.WaitRead): the copy waits there while the connection
// looks idle, and takes its small buffer only once data has arrived, so an
// idle TLS connection holds no relay buffer at all.
type readWaitable interface {
	WaitRead() error
}

// smallReadLen is the data size of the small buffer for these options, or 0
// when a full buffer is no larger.
func smallReadLen(options network.ReadWaitOptions) int {
	small := smallReadSize - options.FrontHeadroom - options.RearHeadroom
	if small < minSmallRead {
		small = minSmallRead
	}
	if options.MTU > 0 && options.MTU <= small {
		return 0
	}
	return small
}

// readSizing chooses the buffer of the next read of a copy.
type readSizing struct {
	full  bool // the next read goes into a full buffer
	short int  // short reads in a row on full buffers
}

// newBuffer returns a full buffer, or a small one with room for small bytes
// of data (0: no small buffer).
func (s *readSizing) newBuffer(options network.ReadWaitOptions, small int) *buf.Buffer {
	if s.full || small == 0 {
		return options.NewBuffer()
	}
	return newSmallBuffer(options, small)
}

// update records a read of n bytes.
func (s *readSizing) update(n, small int) {
	switch {
	case n >= small:
		// a small read that filled its buffer: more is probably waiting
		s.full, s.short = true, 0
	case s.full:
		// short reads in a row on a full buffer: the burst is over
		s.short++
		if s.short >= shortReadsToShrink {
			s.full, s.short = false, 0
		}
	}
}

// newSmallBuffer is ReadWaitOptions.NewBuffer with room for size bytes of
// data.
func newSmallBuffer(options network.ReadWaitOptions, size int) *buf.Buffer {
	buffer := buf.NewSize(options.FrontHeadroom + size + options.RearHeadroom)
	if options.FrontHeadroom > 0 {
		buffer.Resize(options.FrontHeadroom, 0)
	}
	if options.RearHeadroom > 0 {
		buffer.Reserve(options.RearHeadroom)
	}
	return buffer
}

func countAll(readCounters, writeCounters []network.CountFunc, n int) {
	for _, counter := range readCounters {
		counter(int64(n))
	}
	for _, counter := range writeCounters {
		counter(int64(n))
	}
}
