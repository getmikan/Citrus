// Adapted from XTLS/Xray-core at 92ccc939aaf4; SPDX-License-Identifier: MPL-2.0

package xdrive

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

const testPatience = 30 * time.Second

func settings(folder string) *Config {
	return &Config{RemoteFolder: folder, Service: "local", FlushIntervalMs: 5, PollIntervalMs: 5, MaxPollIntervalMs: 20, SessionTtlSeconds: 5}
}
func pair(t *testing.T) (net.Conn, net.Conn, func()) {
	t.Helper()
	return pairWith(t, settings(t.TempDir()))
}
func pairWith(t *testing.T, cfg *Config) (net.Conn, net.Conn, func()) {
	t.Helper()
	l, err := Listen(*cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(*cfg, nil)
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testPatience)
	defer cancel()
	client, err := c.Dial(ctx)
	if err != nil {
		c.Close()
		l.Close()
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() { server, _ := l.Accept(); accepted <- server }()
	select {
	case server := <-accepted:
		return client, server, func() { client.Close(); server.Close(); c.Close(); l.Close() }
	case <-ctx.Done():
		c.Close()
		l.Close()
		t.Fatal(ctx.Err())
		return nil, nil, nil
	}
}
func expectRead(t *testing.T, c net.Conn, want string) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(testPatience))
	b := make([]byte, len(want))
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != want {
		t.Fatalf("got %q want %q", b, want)
	}
}
func TestRoundTrip(t *testing.T) {
	client, server, cleanup := pair(t)
	defer cleanup()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	expectRead(t, server, "ping")

	if _, err := server.Write([]byte("pong")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	expectRead(t, client, "pong")
}

func TestInterleaved(t *testing.T) {
	client, server, cleanup := pair(t)
	defer cleanup()

	for i := 0; i < 20; i++ {
		if _, err := client.Write([]byte("up")); err != nil {
			t.Fatalf("client write %d: %v", i, err)
		}
		expectRead(t, server, "up")

		if _, err := server.Write([]byte("down")); err != nil {
			t.Fatalf("server write %d: %v", i, err)
		}
		expectRead(t, client, "down")
	}
}

func TestMultiSegmentTransfer(t *testing.T) {
	client, server, cleanup := pair(t)
	defer cleanup()

	payload := make([]byte, 3*defaultSegmentBytes+1234)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	go func() {
		client.Write(payload)
	}()

	if err := server.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestCloseEOF(t *testing.T) {
	client, server, cleanup := pair(t)
	defer cleanup()

	if _, err := client.Write([]byte("bye")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "bye" {
		t.Fatalf("read %q, want %q", got, "bye")
	}
}

func TestReadDeadline(t *testing.T) {
	client, _, cleanup := pair(t)
	defer cleanup()

	if err := client.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := client.Read(buf); !os.IsTimeout(err) {
		t.Fatalf("Read returned %v, want a timeout", err)
	}
}

func TestLocalNameEscape(t *testing.T) {
	root := t.TempDir()
	storage, err := newLocalStorage(root)
	if err != nil {
		t.Fatalf("newLocalStorage: %v", err)
	}

	if err := storage.Put(context.Background(), "../escaped", []byte("x")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := os.Stat(root + "/escaped"); err != nil {
		t.Fatalf("name was not clamped inside the root: %v", err)
	}
}

func TestLocalMissingObject(t *testing.T) {
	storage, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatalf("newLocalStorage: %v", err)
	}

	if _, err := storage.Get(context.Background(), "nothing/here"); err != errNotFound {
		t.Fatalf("Get returned %v, want errNotFound", err)
	}
	names, err := storage.List(context.Background(), "nothing")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("List returned %v, want none", names)
	}
}

func TestResumeAfterIdle(t *testing.T) {
	client, server, cleanup := pair(t)
	defer cleanup()

	if _, err := client.Write([]byte("first")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	expectRead(t, server, "first")

	time.Sleep(200 * time.Millisecond)

	if _, err := client.Write([]byte("second")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	expectRead(t, server, "second")
}

func TestParseEntry(t *testing.T) {
	cases := []struct {
		name string
		seq  int64
		ok   bool
	}{
		{"000000000.seg", 0, true},
		{"000000042.seg", 42, true},
		{"000000007.end", 7, true},
		{"000000001.tmp", 0, false},
		{"notanumber.seg", 0, false},
		{"000000001", 0, false},
	}
	for _, c := range cases {
		seq, ok := parseEntry(c.name)
		if ok != c.ok || (ok && seq != c.seq) {
			t.Fatalf("parseEntry(%q) = %d, %v; want %d, %v", c.name, seq, ok, c.seq, c.ok)
		}
	}
}

func TestParamDefaults(t *testing.T) {
	p := paramsFromConfig(&Config{})
	if p.segmentBytes != defaultSegmentBytes || p.flushInterval != defaultFlushInterval {
		t.Fatalf("defaults not applied: %+v", p)
	}

	p = paramsFromConfig(&Config{SegmentBytes: 1 << 30, PollIntervalMs: 400, MaxPollIntervalMs: 100})
	if p.segmentBytes != maxSegmentBytes {
		t.Fatalf("segmentBytes is %d, want %d", p.segmentBytes, maxSegmentBytes)
	}
	if p.maxPollInterval < p.minPollInterval {
		t.Fatalf("maxPollInterval %v below minPollInterval %v", p.maxPollInterval, p.minPollInterval)
	}
}

func TestMissingSegment(t *testing.T) {
	storage, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatalf("newLocalStorage: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := paramsFromConfig(&Config{PollIntervalMs: 5, MaxPollIntervalMs: 20, HoleTimeoutMs: 200})
	if err := storage.Put(ctx, objectName("hole", 1, segSuffix), []byte("second")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	reader := newWALReader(ctx, storage, "hole", p)
	select {
	case _, ok := <-reader.ch:
		if ok {
			t.Fatal("delivered data past a missing segment")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not give up on a missing segment")
	}

	err = reader.Err()
	if err == nil || err == io.EOF {
		t.Fatalf("Err returned %v, want a failure", err)
	}
}

func TestIdleStreamWaits(t *testing.T) {
	storage, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatalf("newLocalStorage: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := paramsFromConfig(&Config{PollIntervalMs: 5, MaxPollIntervalMs: 20, HoleTimeoutMs: 100})
	reader := newWALReader(ctx, storage, "idle", p)

	time.Sleep(400 * time.Millisecond)
	if err := storage.Put(ctx, objectName("idle", 0, segSuffix), []byte("late")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	select {
	case data, ok := <-reader.ch:
		if !ok {
			t.Fatalf("the reader gave up on an idle stream: %v", reader.Err())
		}
		if string(data) != "late" {
			t.Fatalf("read %q, want %q", data, "late")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reader missed a late segment")
	}
}

func TestFailureMarker(t *testing.T) {
	storage, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatalf("newLocalStorage: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := paramsFromConfig(&Config{PollIntervalMs: 5, MaxPollIntervalMs: 20})
	if err := storage.Put(ctx, objectName("broken", 0, segSuffix), []byte("first")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := storage.Put(ctx, objectName("broken", 1, errSuffix), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	reader := newWALReader(ctx, storage, "broken", p)

	select {
	case data, ok := <-reader.ch:
		if !ok || string(data) != "first" {
			t.Fatalf("want the segment before the marker, got %q %v", data, ok)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not deliver the first segment")
	}

	select {
	case _, ok := <-reader.ch:
		if ok {
			t.Fatal("delivered data past the failure marker")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not stop on the failure marker")
	}

	if err := reader.Err(); err == nil || err == io.EOF {
		t.Fatalf("Err returned %v, want a failure", err)
	}
}

type inlineOnlyStorage struct {
	Storage
	gets int64
}

func (s *inlineOnlyStorage) List(ctx context.Context, prefix string) ([]Entry, error) {
	return []Entry{{Name: "000000000" + segSuffix, Inline: []byte("carried by the listing")}}, nil
}

func (s *inlineOnlyStorage) Get(ctx context.Context, name string) ([]byte, error) {
	atomic.AddInt64(&s.gets, 1)
	return nil, errNotFound
}

func (s *inlineOnlyStorage) Delete(ctx context.Context, name string) error {
	return nil
}

func TestInlinePayload(t *testing.T) {
	base, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatalf("newLocalStorage: %v", err)
	}
	storage := &inlineOnlyStorage{Storage: base}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader := newWALReader(ctx, storage, "inline", paramsFromConfig(&Config{PollIntervalMs: 5}))
	select {
	case data, ok := <-reader.ch:
		if !ok {
			t.Fatalf("reader stopped: %v", reader.Err())
		}
		if string(data) != "carried by the listing" {
			t.Fatalf("read %q, want the inline payload", data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not deliver the inline payload")
	}

	if got := atomic.LoadInt64(&storage.gets); got != 0 {
		t.Fatalf("called Get %d times for an inline payload", got)
	}
}
