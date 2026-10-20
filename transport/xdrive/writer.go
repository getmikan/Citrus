package xdrive

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
)

type segment struct {
	seq  int64
	data []byte
}

// A fixed number of workers and a bounded queue apply backpressure before
// allocating another segment, rather than spawning a goroutine per Write.
type walWriter struct {
	ctx     context.Context
	storage Storage
	prefix  string
	params
	deadline *deadline.PipeDeadline
	mu       sync.Mutex
	buf      []byte
	seq      int64
	closed   bool
	queue    chan segment
	stop     chan struct{}
	failed   chan struct{}
	workers  sync.WaitGroup
	errMu    sync.Mutex
	err      error
}

func newWALWriter(ctx context.Context, storage Storage, prefix string, p params, d *deadline.PipeDeadline) *walWriter {
	w := &walWriter{ctx: ctx, storage: storage, prefix: prefix, params: p, deadline: d, queue: make(chan segment, p.concurrency), stop: make(chan struct{}), failed: make(chan struct{})}
	for i := 0; i < p.concurrency; i++ {
		w.workers.Add(1)
		go w.uploadLoop()
	}
	go w.flushLoop()
	return w
}
func (w *walWriter) Err() error { w.errMu.Lock(); defer w.errMu.Unlock(); return w.err }
func (w *walWriter) fail(err error) {
	w.errMu.Lock()
	defer w.errMu.Unlock()
	if w.err == nil {
		w.err = err
		close(w.failed)
	}
}
func (w *walWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, net.ErrClosed
	}
	total := 0
	for len(p) > 0 {
		if err := w.Err(); err != nil {
			return total, err
		}
		select {
		case <-w.ctx.Done():
			return total, net.ErrClosed
		case <-w.deadline.Wait():
			return total, os.ErrDeadlineExceeded
		default:
		}
		n := min(len(p), w.segmentBytes-len(w.buf))
		w.buf = append(w.buf, p[:n]...)
		p = p[n:]
		total += n
		if len(w.buf) == w.segmentBytes {
			if err := w.flushLocked(); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}
func (w *walWriter) flushLocked() error {
	if len(w.buf) == 0 {
		return nil
	}
	select {
	case w.queue <- segment{seq: w.seq, data: w.buf}:
		w.seq++
		w.buf = nil
		return nil
	case <-w.ctx.Done():
		return net.ErrClosed
	case <-w.failed:
		return w.Err()
	case <-w.deadline.Wait():
		return os.ErrDeadlineExceeded
	}
}
func (w *walWriter) flushLoop() {
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-w.stop:
			return
		case <-ticker.C:
			w.mu.Lock()
			if !w.closed {
				_ = w.flushLocked()
			}
			w.mu.Unlock()
		}
	}
}
func (w *walWriter) uploadLoop() {
	defer w.workers.Done()
	for {
		select {
		case <-w.ctx.Done():
			return
		case item, ok := <-w.queue:
			if !ok {
				return
			}
			if err := w.storage.Put(w.ctx, objectName(w.prefix, item.seq, segSuffix), item.data); err != nil {
				w.fail(newError("failed to store segment").Base(err))
				_ = w.storage.Put(w.ctx, objectName(w.prefix, item.seq, errSuffix), nil)
				return
			}
		}
	}
}
func (w *walWriter) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	close(w.stop)
	err := w.flushLocked()
	close(w.queue)
	seq := w.seq
	w.mu.Unlock()
	w.workers.Wait()
	if err != nil {
		return err
	}
	if err = w.Err(); err != nil {
		return err
	}
	if w.ctx.Err() != nil {
		return io.ErrClosedPipe
	}
	return w.storage.Put(w.ctx, objectName(w.prefix, seq, endSuffix), nil)
}
