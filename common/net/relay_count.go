package net

import (
	"io"
	"syscall"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	"github.com/metacubex/sing/common/network"
)

// copyCounted is copyConn (bufio.Copy) that keeps the read counters of source
// exact.
//
// A traffic tracker (tunnel/statistic) lets the copy unwrap it down to the
// remote connection and hands over counters (per-connection, global and
// per-user totals). The copy calls them for a buffer only after the write of
// that buffer to destination succeeded, so a buffer whose write reports an
// error is never counted, although it was read from the remote and may well
// have been delivered: an HTTP/2 stream (sing-mux h2mux) returns "stream
// closed" for a DATA frame that is already on the wire when the client resets
// the stream before the server hears back from the frame writer. Such a
// destination is wrapped so that a failed write still counts the bytes it was
// given. The wrapper stays out of the way (the copy unwraps it) once the
// destination unwraps to a socket, where a failed write delivered nothing and
// splice must stay possible.
func copyCounted(destination io.Writer, source io.Reader) (int64, error) {
	if _, counters := network.UnwrapCountReader(source, nil); len(counters) > 0 {
		destination = &countOnFailWriter{
			writer:   bufio.NewExtendedWriter(destination),
			upstream: destination,
			counters: counters,
		}
	}
	return copyConn(destination, source)
}

// countOnFailWriter calls counters with the size of every write that fails;
// successful writes are counted by the copy itself.
type countOnFailWriter struct {
	writer   network.ExtendedWriter
	upstream io.Writer
	counters []network.CountFunc
}

func (w *countOnFailWriter) count(n int) {
	for _, counter := range w.counters {
		counter(int64(n))
	}
}

func (w *countOnFailWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if err != nil {
		w.count(len(p))
	}
	return n, err
}

func (w *countOnFailWriter) WriteBuffer(buffer *buf.Buffer) error {
	n := buffer.Len()
	err := w.writer.WriteBuffer(buffer)
	if err != nil {
		w.count(n)
	}
	return err
}

// Upstream exposes the destination, so headroom and MTU are calculated
// through the wrapper.
func (w *countOnFailWriter) Upstream() any { return w.upstream }

// WriterReplaceable lets the copy unwrap the wrapper once the destination
// unwraps to a socket.
func (w *countOnFailWriter) WriterReplaceable() bool {
	_, isSyscall := network.UnwrapWriter(w.upstream).(syscall.Conn)
	return isSyscall
}

// WriterPossiblyReplaceable keeps the copy re-checking a destination that may
// become a socket later (VLESS Vision).
func (w *countOnFailWriter) WriterPossiblyReplaceable() bool {
	r, ok := network.UnwrapWriter(w.upstream).(network.WriterPossiblyReplaceable)
	return ok && r.WriterPossiblyReplaceable()
}
