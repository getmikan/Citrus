package net

import (
	"bytes"
	"errors"
	"io"
	mrand "math/rand"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	"github.com/metacubex/sing/common/network"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tcpPair returns the two ends of a loopback TCP connection.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		accepted <- c
	}()
	a, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	b := <-accepted
	require.NotNil(t, b)
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a.(*net.TCPConn), b.(*net.TCPConn)
}

// readAllAsync reads c until EOF.
func readAllAsync(c net.Conn) <-chan []byte {
	ch := make(chan []byte, 1)
	go func() {
		got, _ := io.ReadAll(c)
		ch <- got
	}()
	return ch
}

// TestCopyConnBatchedLargeTransfer copies a non-socket source to a socket,
// which goes through the batched copy, with reads of every size.
func TestCopyConnBatchedLargeTransfer(t *testing.T) {
	for _, max := range []int{700, 2048, 16 << 10, 64 << 10} {
		data := randomBytes(t, 8<<20+123)
		src := &chunkReader{data: data, max: max, rng: mrand.New(mrand.NewSource(int64(max)))}
		dst, peer := tcpPair(t)
		got := readAllAsync(peer)
		n, err := copyConn(dst, src)
		require.NoError(t, err)
		require.NoError(t, dst.CloseWrite())
		assert.Equal(t, int64(len(data)), n, "chunks up to %d", max)
		assert.True(t, bytes.Equal(data, <-got), "chunks up to %d: data differs", max)
	}
}

// TestCopyConnBatchedBufferSizes checks that the batched copy keeps the
// buffer choice of the copy loop, and hands the source back to it when a
// burst ends.
func TestCopyConnBatchedBufferSizes(t *testing.T) {
	reads := []int{100}
	for left := 100 << 10; left > 0; left -= 16 << 10 {
		reads = append(reads, minInt(16<<10, left))
	}
	reads = append(reads, 300, 1000, 200, 5000, 100, 100, 50)
	total := 0
	for _, r := range reads {
		total += r
	}
	src := &scriptReader{reads: append([]int(nil), reads...)}
	dst, peer := tcpPair(t)
	got := readAllAsync(peer)
	n, err := copyConn(dst, src)
	require.NoError(t, err)
	require.NoError(t, dst.CloseWrite())
	assert.Equal(t, int64(total), n)
	assert.Len(t, <-got, total)

	small, full := smallReadSize, buf.BufferSize
	want := []int{
		small,                        // 100 B
		small,                        // the first 2 KiB of the burst: batched from here
		full,                         // the rest of that record
		full, full, full, full, full, // the other 16 KiB records
		full,  // the 4 KiB tail of the burst
		full,  // 300 B
		full,  // 1000 B: two short reads, handed back
		small, // 200 B
		small, // 2 KiB of 5000: batched again
		full,  // the other 2952 B
		full,  // 100 B
		full,  // 100 B: handed back
		small, // 50 B
		small, // the EOF
	}
	assert.Equal(t, want, src.caps)
}

// recordingWriter is a vectorised writer that records the size of every
// batch and waits for release before its first write.
type recordingWriter struct {
	w       io.Writer
	release chan struct{}
	once    sync.Once
	batches []int
}

func (w *recordingWriter) wait() { w.once.Do(func() { <-w.release }) }

func (w *recordingWriter) Write(b []byte) (int, error) {
	w.wait()
	w.batches = append(w.batches, 1)
	return w.w.Write(b)
}

func (w *recordingWriter) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	_, err := w.Write(buffer.Bytes())
	return err
}

func (w *recordingWriter) WriteVectorised(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	w.wait()
	w.batches = append(w.batches, len(buffers))
	for _, b := range buffers {
		if _, err := w.w.Write(b.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// signalReader is a chunkReader that reports every read.
type signalReader struct {
	*chunkReader
	reads chan struct{}
}

func (r *signalReader) Read(b []byte) (int, error) {
	n, err := r.chunkReader.Read(b)
	if err == nil {
		r.reads <- struct{}{}
	}
	return n, err
}

// TestCopyBatchedGathers checks that the buffers read while a write is in
// progress go out together, bounded by the read-ahead, and in order.
func TestCopyBatchedGathers(t *testing.T) {
	data := randomBytes(t, 1<<20)
	src := &signalReader{
		chunkReader: &chunkReader{data: data, max: 1 << 30, rng: mrand.New(mrand.NewSource(1))},
		reads:       make(chan struct{}, 1024),
	}
	var out bytes.Buffer
	dst := &recordingWriter{w: &out, release: make(chan struct{})}
	reader := bufio.NewExtendedReader(&scriptLimit{src, 16 << 10})
	options := network.NewReadWaitOptions(reader, dst)
	sizing := readSizing{full: true}
	go func() {
		// let the reader fill the read-ahead before the first write returns
		for i := 0; i < readAheadBuffers+1; i++ {
			<-src.reads
		}
		time.Sleep(50 * time.Millisecond)
		close(dst.release)
		for range src.reads {
		}
	}()
	n, handedBack, err := copyBatched(dst, dst, reader, options, nil, nil, &sizing, smallReadLen(options))
	close(src.reads)
	require.NoError(t, err)
	assert.False(t, handedBack)
	assert.Equal(t, int64(len(data)), n)
	assert.True(t, bytes.Equal(data, out.Bytes()), "data differs")
	maxBatch := 0
	for _, b := range dst.batches {
		maxBatch = max(maxBatch, b)
	}
	assert.Greater(t, maxBatch, 1, "batches %v", dst.batches)
	assert.LessOrEqual(t, maxBatch, readAheadBuffers+1)
}

// scriptLimit hands out at most limit bytes per read, as a TLS record does.
type scriptLimit struct {
	r     io.Reader
	limit int
}

func (r *scriptLimit) Read(b []byte) (int, error) {
	if len(b) > r.limit {
		b = b[:r.limit]
	}
	return r.r.Read(b)
}

// endlessSource returns full reads until it is closed.
type endlessSource struct {
	closed chan struct{}
}

func (s *endlessSource) Read(b []byte) (int, error) {
	select {
	case <-s.closed:
		return 0, net.ErrClosed
	default:
		return len(b), nil
	}
}

// TestCopyBatchedWriteError checks that a failed write ends the copy with the
// write error, and that the reader goroutine exits.
func TestCopyBatchedWriteError(t *testing.T) {
	dst, peer := tcpPair(t)
	require.NoError(t, peer.SetLinger(0))
	require.NoError(t, peer.Close()) // writes fail (reset) soon
	src := &endlessSource{closed: make(chan struct{})}
	before := runtime.NumGoroutine()
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err = copyConn(dst, src)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		close(src.closed)
		t.Fatal("the copy did not end on the write error")
	}
	require.Error(t, err)
	assert.False(t, errors.Is(err, net.ErrClosed), "the write error, not the source's: %v", err)
	close(src.closed)
	// not assert.Eventually: it runs the condition on a goroutine of its own
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	assert.LessOrEqual(t, runtime.NumGoroutine(), before, "the reader goroutine did not exit")
}
