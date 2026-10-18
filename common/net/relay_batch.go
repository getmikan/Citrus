package net

import (
	"errors"
	"io"
	"net"
	"syscall"

	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	"github.com/metacubex/sing/common/network"
)

// readAheadBuffers is how many buffers the reader of a batched copy may hold
// ahead of the writer: up to 256 KiB of pool buffers per direction while a
// transfer runs, none while the connection is idle.
const readAheadBuffers = 8

// errHandBack ends a read-ahead: the reader saw the burst end and leaves the
// source to the copy loop again.
var errHandBack = errors.New("read-ahead handed back")

// batchWriter returns a vectorised writer for destination when the batched
// copy can be used: destination unwraps to a socket (writev), the read side is
// not a socket (it goes through copyAdaptive, a decrypting or decoding
// connection), and buffers may be held ahead.
func batchWriter(destination io.Writer) network.VectorisedWriter {
	if common.LowMemory {
		return nil
	}
	switch upstream := network.UnwrapWriter(destination).(type) {
	case *net.TCPConn:
		return &tcpVectorisedWriter{upstream}
	case syscall.Conn:
		if writer, ok := bufio.CreateVectorisedWriter(upstream); ok {
			return writer
		}
	}
	return nil
}

// tcpVectorisedWriter is bufio.NetVectorisedWriterWrapper: one writev(2) for
// all buffers through the runtime's poller.
type tcpVectorisedWriter struct{ conn *net.TCPConn }

func (w *tcpVectorisedWriter) WriteVectorised(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	data := net.Buffers(buf.ToSliceMulti(buffers))
	_, err := data.WriteTo(w.conn)
	return err
}

// readAhead is the reader half of a batched copy (copyBatched).
type readAhead struct {
	ch   chan *buf.Buffer // read buffers, in order; closed when the reader exits
	stop chan struct{}    // closed by the writer when it gives up
	err  error            // why the reader exited; read after ch is closed
}

// run reads source into ch until a read fails, the writer stops, or a burst
// ends (errHandBack, sizing back on the small buffer).
func (r *readAhead) run(source network.ExtendedReader, options network.ReadWaitOptions, sizing *readSizing, small int) {
	defer func() {
		select {
		case <-r.stop:
			r.drain()
		default:
		}
		close(r.ch)
	}()
	var yield relayYield
	for {
		buffer := sizing.newBuffer(options, small)
		err := source.ReadBuffer(buffer)
		if err != nil {
			buffer.Release()
			r.err = err
			return
		}
		options.PostReturn(buffer)
		dataLen := buffer.Len()
		sizing.update(dataLen, small)
		select {
		case <-r.stop: // checked first: both cases below may be ready
			buffer.Release()
			return
		default:
		}
		select {
		case r.ch <- buffer:
		case <-r.stop:
			buffer.Release()
			return
		}
		if !sizing.full {
			r.err = errHandBack
			return
		}
		yield.add(dataLen)
	}
}

// drain releases the buffers left in ch after the writer stopped. Both
// halves call it: the writer when it stops, the reader when it exits after
// that, so what the reader sent in between is released too.
func (r *readAhead) drain() {
	for {
		select {
		case buffer, ok := <-r.ch:
			if !ok {
				return
			}
			buffer.Release()
		default:
			return
		}
	}
}

// copyBatched is the copyAdaptive loop for a transfer in progress: a reader
// goroutine keeps reading (decrypting) the source while the copy writes, and
// every write takes all the buffers read meanwhile in one writev(2).
//
// A TLS or Shadowsocks source returns one record or chunk per read (up to 16
// KiB); written one by one, the upload of a loaded server spends most of its
// time in write(2), each of which carries its segment through the whole
// network stack. The batch never waits for data: the writer takes what is
// already read and writes it, so a lone record goes out as soon as it is
// decrypted, as before. The reader stays at most readAheadBuffers ahead
// (backpressure), and hands the source back to the copy loop when the burst
// ends, so an idle connection waits on the small buffer without a goroutine.
//
// handedBack reports that the source is the caller's again (no error); any
// other return ends the copy. After a write error the reader is still blocked
// on the source until the relay closes it; it then releases its buffers.
func copyBatched(destination network.ExtendedWriter, writer network.VectorisedWriter, source network.ExtendedReader, options network.ReadWaitOptions, readCounters []network.CountFunc, writeCounters []network.CountFunc, sizing *readSizing, small int) (n int64, handedBack bool, err error) {
	r := &readAhead{
		ch:   make(chan *buf.Buffer, readAheadBuffers),
		stop: make(chan struct{}),
	}
	readerSizing := *sizing
	go r.run(source, options, &readerSizing, small)
	batch := make([]*buf.Buffer, 0, readAheadBuffers+1)
	var yield relayYield
	for {
		buffer, ok := <-r.ch
		if !ok {
			// The reader exited (closing ch publishes r.err and its sizing).
			*sizing = readerSizing
			if r.err == errHandBack {
				return n, true, nil
			}
			err = r.err
			if errors.Is(err, io.EOF) {
				err = nil
			}
			return
		}
		batch = append(batch[:0], buffer)
	gather:
		for len(batch) < cap(batch) {
			select {
			case buffer, ok = <-r.ch:
				if !ok {
					break gather // written below, then the closed ch ends the loop
				}
				batch = append(batch, buffer)
			default:
				break gather
			}
		}
		dataLen := buf.LenMulti(batch)
		if len(batch) == 1 {
			err = destination.WriteBuffer(batch[0])
			if err != nil {
				batch[0].Leak()
			}
		} else {
			err = writer.WriteVectorised(batch) // releases the buffers
		}
		clear(batch)
		if err != nil {
			close(r.stop)
			r.drain()
			return
		}
		n += int64(dataLen)
		countAll(readCounters, writeCounters, dataLen)
		yield.add(dataLen)
	}
}
