package sudoku

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
)

type limitedWriteConn struct {
	mockConn
	largest int
	calls   int
	short   int
	failAt  int
}

func (c *limitedWriteConn) Write(p []byte) (int, error) {
	c.calls++
	c.largest = max(c.largest, len(p))
	if c.calls == c.failAt {
		return 0, io.ErrClosedPipe
	}
	if c.short > 0 {
		p = p[:min(len(p), c.short)]
	}
	return c.mockConn.Write(p)
}

func testObfsConn(packed bool, raw net.Conn, table *Table, padding int) net.Conn {
	if packed {
		return NewPackedConn(raw, table, padding, padding)
	}
	return NewConn(raw, table, padding, padding, false)
}

func TestLargeWritesUseBoundedChunks(t *testing.T) {
	for _, packed := range []bool{false, true} {
		for _, padding := range []int{0, 100} {
			t.Run(fmt.Sprintf("packed=%v/padding=%d", packed, padding), func(t *testing.T) {
				table := NewTable("large-write-regression", "prefer_ascii")
				raw := &limitedWriteConn{}
				writer := testObfsConn(packed, raw, table, padding)
				payload := make([]byte, 2*maxWriteChunk+17)
				for n := range payload {
					payload[n] = byte(n)
				}
				n, err := writer.Write(payload)
				if err != nil || n != len(payload) {
					t.Fatalf("Write = %d, %v", n, err)
				}
				if raw.calls < 3 || raw.largest > 9*maxWriteChunk+64 {
					t.Fatalf("unbounded encoded write: calls=%d largest=%d", raw.calls, raw.largest)
				}
				reader := testObfsConn(packed, &mockConn{readBuf: raw.writeBuf}, table, padding)
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(reader, got); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatal("chunking changed decoded payload")
				}
			})
		}
	}
}

func TestEncodedShortWritesAreCompleted(t *testing.T) {
	for _, packed := range []bool{false, true} {
		table := NewTable("short-write-regression", "prefer_ascii")
		raw := &limitedWriteConn{short: 17}
		writer := testObfsConn(packed, raw, table, 20)
		payload := bytes.Repeat([]byte("data"), 300)
		if n, err := writer.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("Write = %d, %v", n, err)
		}
		reader := testObfsConn(packed, &mockConn{readBuf: raw.writeBuf}, table, 20)
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(reader, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("short write lost encoded data")
		}
	}
}

func TestChunkFailureReportsCompletedInput(t *testing.T) {
	for _, packed := range []bool{false, true} {
		raw := &limitedWriteConn{failAt: 2}
		writer := testObfsConn(packed, raw, NewTable("failed-write-regression", "prefer_ascii"), 0)
		n, err := writer.Write(make([]byte, maxWriteChunk+1))
		if n != maxWriteChunk || !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
}
