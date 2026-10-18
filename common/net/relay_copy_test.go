package net

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/network"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chunkReader hands out data in chunks of random size (up to max) and records
// the free space of every buffer it is given.
type chunkReader struct {
	data []byte
	max  int
	rng  *mrand.Rand
	caps []int
}

func (r *chunkReader) Read(b []byte) (int, error) {
	r.caps = append(r.caps, len(b))
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := 1 + r.rng.Intn(r.max)
	n = minInt(minInt(n, len(b)), len(r.data))
	copy(b, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

// onlyWriter hides everything but Write (not a socket, no WriteBuffer).
type onlyWriter struct{ w io.Writer }

func (w onlyWriter) Write(b []byte) (int, error) { return w.w.Write(b) }

func randomBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func TestCopyConnLargeTransfer(t *testing.T) {
	for _, max := range []int{1, 700, 2048, 16 << 10, 64 << 10} {
		data := randomBytes(t, 8<<20+123)
		if max == 1 {
			data = data[:200<<10]
		}
		src := &chunkReader{data: data, max: max, rng: mrand.New(mrand.NewSource(int64(max)))}
		var dst bytes.Buffer
		n, err := copyConn(onlyWriter{&dst}, src)
		require.NoError(t, err)
		assert.Equal(t, int64(len(data)), n, "chunks up to %d", max)
		assert.True(t, bytes.Equal(data, dst.Bytes()), "chunks up to %d: data differs", max)
	}
}

// scriptReader returns the given reads one by one and records the free space
// of every buffer it is given.
type scriptReader struct {
	reads []int
	caps  []int
}

func (r *scriptReader) Read(b []byte) (int, error) {
	r.caps = append(r.caps, len(b))
	if len(r.reads) == 0 {
		return 0, io.EOF
	}
	n := minInt(r.reads[0], len(b))
	r.reads[0] -= n
	if r.reads[0] == 0 {
		r.reads = r.reads[1:]
	}
	return n, nil
}

// TestCopyConnBufferSizes checks the buffer a read waits on: small after a
// short message or at the start, full while a burst fills its buffers.
func TestCopyConnBufferSizes(t *testing.T) {
	// a 100 B message, a 100 KiB burst in 16 KiB records, a 300 B, a 1000 B
	// and a 200 B message
	reads := []int{100}
	for left := 100 << 10; left > 0; left -= 16 << 10 {
		reads = append(reads, minInt(16<<10, left))
	}
	reads = append(reads, 300, 1000, 200)
	src := &scriptReader{reads: append([]int(nil), reads...)}
	n, err := copyConn(io.Discard, src)
	require.NoError(t, err)
	assert.Equal(t, int64(100+100<<10+300+1000+200), n)

	small, full := smallReadSize, buf.BufferSize
	want := []int{
		small,                        // the first read: 100 B
		small,                        // the first 2 KiB of the burst fill it
		full,                         // the rest of that record
		full, full, full, full, full, // the other 16 KiB records
		full,  // the 4 KiB tail of the burst
		full,  // 300 B: one short read keeps the full buffer
		full,  // 1000 B: two short reads in a row
		small, // 200 B
		small, // the EOF
	}
	assert.Equal(t, want, src.caps)
}

// failingWriter accepts limit bytes and then fails every write.
type failingWriter struct {
	limit   int
	written int
}

func (w *failingWriter) Write(b []byte) (int, error) {
	if w.written+len(b) > w.limit {
		return 0, errors.New("stream closed")
	}
	w.written += len(b)
	return len(b), nil
}

// countedReader is a traffic counter in front of a reader, as a tracker is.
type countedReader struct {
	io.Reader
	count func(int64)
}

func (r countedReader) UnwrapReader() (io.Reader, []network.CountFunc) {
	return r.Reader, []network.CountFunc{r.count}
}

// TestCopyCountedCountsFailedWrite checks that the adaptive copy keeps the
// counting of copyCounted: every successful write once, and the buffer of a
// failed write too.
func TestCopyCountedCountsFailedWrite(t *testing.T) {
	data := randomBytes(t, 1<<20)
	src := &chunkReader{data: data, max: 20 << 10, rng: mrand.New(mrand.NewSource(int64(7)))}
	var counted int64
	dst := &failingWriter{limit: 300 << 10}
	_, err := copyCounted(dst, countedReader{src, func(n int64) { counted += n }})
	require.Error(t, err)
	read := int64(len(data) - len(src.data))
	assert.Equal(t, read, counted, "every byte read is counted, the failed write included")
	assert.Greater(t, read, int64(dst.written))
}

func selfSignedTLS(t *testing.T) *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay.test"},
		DNSNames:     []string{"relay.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// TestRelayTLSHalfClose relays a TLS client (the source the adaptive copy is
// for) to a TCP server: a large upload, a half-close that reaches the
// server, and a large answer after it.
func TestRelayTLSHalfClose(t *testing.T) {
	upload := randomBytes(t, 6<<20+17)
	download := randomBytes(t, 5<<20+3)

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer upstream.Close()
	var upstreamGot []byte
	var upstreamErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := upstream.Accept()
		if err != nil {
			upstreamErr = err
			return
		}
		defer c.Close()
		upstreamGot, upstreamErr = io.ReadAll(c) // until the client's half-close
		if upstreamErr == nil {
			_, upstreamErr = c.Write(download)
		}
	}()

	front, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer front.Close()
	serverConfig := selfSignedTLS(t)
	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		c, err := front.Accept()
		if err != nil {
			return
		}
		left := tls.Server(c, serverConfig)
		if err := left.Handshake(); err != nil {
			_ = left.Close()
			return
		}
		right, err := net.Dial("tcp", upstream.Addr().String())
		if err != nil {
			_ = left.Close()
			return
		}
		Relay(left, right)
	}()

	client, err := tls.Dial("tcp", front.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	defer client.Close()
	go func() {
		// writes of various sizes, then a half-close
		rest := upload
		rng := mrand.New(mrand.NewSource(int64(3)))
		for len(rest) > 0 {
			n := minInt(1+rng.Intn(40<<10), len(rest))
			if _, err := client.Write(rest[:n]); err != nil {
				return
			}
			rest = rest[n:]
		}
		_ = client.CloseWrite()
	}()
	got, err := io.ReadAll(client)
	require.NoError(t, err)
	wg.Wait()
	require.NoError(t, upstreamErr)
	assert.Equal(t, sha256.Sum256(upload), sha256.Sum256(upstreamGot), "upload differs (%d of %d bytes)", len(upstreamGot), len(upload))
	assert.Equal(t, sha256.Sum256(download), sha256.Sum256(got), "download differs (%d of %d bytes)", len(got), len(download))
	select {
	case <-relayDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay did not finish")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// possiblyReader is a reader that Vision may still replace for its first
// reads, so that the copy goes through copyOnce.
type possiblyReader struct {
	*scriptReader
	left int
}

func (r *possiblyReader) Read(b []byte) (int, error) {
	r.left--
	return r.scriptReader.Read(b)
}

func (r *possiblyReader) ReaderPossiblyReplaceable() bool { return r.left > 0 }

// TestCopyConnBufferSizesVision checks the buffer choice while Vision may
// replace the reader, and that it carries over to the copy after it.
func TestCopyConnBufferSizesVision(t *testing.T) {
	src := &possiblyReader{scriptReader: &scriptReader{reads: []int{100, 5000, 100, 5000, 300, 200}}, left: 3}
	n, err := copyConn(io.Discard, src)
	require.NoError(t, err)
	assert.Equal(t, int64(100+5000+100+5000+300+200), n)
	small, full := smallReadSize, buf.BufferSize
	want := []int{
		small, // 100 B, copyOnce
		small, // 2 KiB of 5000, copyOnce
		full,  // the other 2952 B, copyOnce; Vision is done after this read
		full,  // 100 B: the choice carries over
		full,  // 5000 B
		full,  // 300 B
		full,  // 200 B: two short reads in a row
		small, // the EOF
	}
	assert.Equal(t, want, src.caps)
}

// waitingReader is a scriptReader that can wait for data without a buffer
// and records, for every read, whether WaitRead came right before it.
type waitingReader struct {
	scriptReader
	waited      bool
	waitedReads []bool
	waitErr     error
}

func (r *waitingReader) WaitRead() error {
	if r.waitErr != nil {
		return r.waitErr
	}
	r.waited = true
	return nil
}

func (r *waitingReader) Read(b []byte) (int, error) {
	r.waitedReads = append(r.waitedReads, r.waited)
	r.waited = false
	return r.scriptReader.Read(b)
}

// TestCopyConnWaitRead: a source that can wait for data (a TLS conn) is
// waited on before every read into the small buffer, so that an idle
// connection holds no buffer, and read directly while a burst runs on full
// buffers.
func TestCopyConnWaitRead(t *testing.T) {
	reads := []int{100}
	for left := 64 << 10; left > 0; left -= 16 << 10 {
		reads = append(reads, minInt(16<<10, left))
	}
	reads = append(reads, 300, 200, 50)
	src := &waitingReader{scriptReader: scriptReader{reads: reads}}
	n, err := copyConn(io.Discard, src)
	require.NoError(t, err)
	assert.Equal(t, int64(100+64<<10+300+200+50), n)
	require.Equal(t, len(src.caps), len(src.waitedReads))
	for i, c := range src.caps {
		assert.Equal(t, c == smallReadSize, src.waitedReads[i], "read %d (buffer %d)", i, c)
	}

	// the error of the wait ends the copy like the error of a read
	src = &waitingReader{scriptReader: scriptReader{reads: []int{10}}, waitErr: io.EOF}
	n, err = copyConn(io.Discard, src)
	require.NoError(t, err)
	assert.Zero(t, n)
	failed := errors.New("reset")
	src = &waitingReader{scriptReader: scriptReader{reads: []int{10}}, waitErr: failed}
	_, err = copyConn(io.Discard, src)
	assert.ErrorIs(t, err, failed)
}

// queuedSource hands out its buffers in batches through WaitReadBuffers, as
// an AnyTLS stream does with the frames it has queued.
type queuedSource struct {
	batches [][]*buf.Buffer
	calls   int
}

func (s *queuedSource) Read([]byte) (int, error) { panic("Read on a read waiter") }

func (s *queuedSource) InitializeReadWaiter(network.ReadWaitOptions) bool { return false }

func (s *queuedSource) WaitReadBuffer() (*buf.Buffer, error) {
	panic("WaitReadBuffer on a batch source")
}

func (s *queuedSource) WaitReadBuffers() ([]*buf.Buffer, error) {
	s.calls++
	if len(s.batches) == 0 {
		return nil, io.EOF
	}
	b := s.batches[0]
	s.batches = s.batches[1:]
	return b, nil
}

// A source that queues buffers is copied to a socket a batch at a time.
func TestCopyQueuedSourceToSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	received := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		received <- b
	}()
	dst, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	payload := randomBytes(t, 10*1000)
	src := &queuedSource{}
	k := 0
	for _, size := range []int{1, 3, 2, 4} { // 10 buffers of 1000 bytes in 4 batches
		var batch []*buf.Buffer
		for j := 0; j < size; j++ {
			batch = append(batch, buf.As(append([]byte(nil), payload[k*1000:(k+1)*1000]...)))
			k++
		}
		src.batches = append(src.batches, batch)
	}

	n, err := copyConn(dst, src)
	require.NoError(t, err)
	require.Equal(t, int64(len(payload)), n)
	require.Equal(t, 5, src.calls) // four batches and the EOF
	dst.Close()
	require.True(t, bytes.Equal(payload, <-received))
}
