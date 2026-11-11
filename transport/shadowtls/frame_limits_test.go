package shadowtls

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestReadFrameRejectsOversizedRecordBeforeBody(t *testing.T) {
	for _, size := range []int{maxTLSCiphertext + 1, 65535} {
		wire := make([]byte, tlsHeaderSize+size)
		wire[0] = applicationData
		binary.BigEndian.PutUint16(wire[3:], uint16(size))
		source := bytes.NewReader(wire)
		if _, err := readFrame(source); err == nil {
			t.Fatalf("accepted oversized record: %d", size)
		}
		if source.Len() != size {
			t.Fatal("oversized body was read before rejecting the header")
		}
	}
}

func TestReadFrameUsesBoundedCallerBuffer(t *testing.T) {
	wire := make([]byte, maxTLSFrame)
	wire[0] = applicationData
	binary.BigEndian.PutUint16(wire[3:], maxTLSCiphertext)
	for i := tlsHeaderSize; i < len(wire); i++ {
		wire[i] = byte(i)
	}
	buffer := make([]byte, maxTLSFrame)
	frame, err := readFrameBuffer(bytes.NewReader(wire), buffer)
	if err != nil || !bytes.Equal(frame, wire) {
		t.Fatalf("maximum legal record changed: %v", err)
	}
	if &frame[0] != &buffer[0] {
		t.Fatal("pre-authentication reader did not use the caller's leased buffer")
	}
}
