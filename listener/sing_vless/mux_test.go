package sing_vless

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
)

func TestMuxConcurrentResponseWrites(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	b.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := &serverConn{ExtendedConn: bufio.NewExtendedConn(a)}
	writer := bufio.NewExtendedWriter(&muxWriteConn{Conn: response})
	const count = 32
	payload := bytes.Repeat([]byte("frame"), 2000)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buffer := buf.As(append([]byte(nil), payload...))
			if err := writer.WriteBuffer(buffer); err != nil {
				t.Error(err)
			}
		}()
	}
	got := make([]byte, 2+count*len(payload))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if got[0] != 0 || got[1] != 0 || !bytes.Equal(got[2:], bytes.Repeat(payload, count)) {
		t.Fatal("concurrent writes interleaved the VLESS response")
	}
}
