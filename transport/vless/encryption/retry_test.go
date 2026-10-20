package encryption

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestFailedResumptionExpiresOnlyItsOwnTicket(t *testing.T) {
	for _, renewed := range []bool{false, true} {
		for _, partialHeader := range []bool{false, true} {
			a, b := net.Pipe()
			client := &ClientInstance{PfsKey: bytes.Repeat([]byte{1}, 64), Expire: time.Now().Add(time.Hour)}
			conn := NewCommonConn(a, true)
			conn.Client = client
			conn.UnitedKey = append(append([]byte(nil), client.PfsKey...), make([]byte, 32)...)
			if renewed {
				client.PfsKey = bytes.Repeat([]byte{2}, 64)
			}
			if partialHeader {
				conn.PeerAEAD = &AEAD{}
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer b.Close()
				if partialHeader {
					b.Write([]byte{23, 3})
				}
			}()
			_, err := conn.Read(make([]byte, 1))
			a.Close()
			<-done
			if !errors.Is(err, ErrNewHandshakeNeeded) || !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("unexpected retry error: %v", err)
			}
			if time.Now().Before(client.Expire) != renewed {
				t.Fatalf("renewed=%v: wrong ticket invalidated", renewed)
			}
		}
	}
}
