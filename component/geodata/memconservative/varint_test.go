package memconservative

import (
	"bytes"
	"testing"
)

func TestDecodeRejectsOverlongVarint(t *testing.T) {
	// A record tag followed by a megabyte of continuation bytes: rejected
	// after ten bytes instead of being buffered to the end of the file.
	data := append([]byte{10}, bytes.Repeat([]byte{0x80}, 1<<20)...)
	_, err := Decode(writeTemp(t, data), "cn")
	if err != errInvalidGeodataVarintLength {
		t.Fatalf("want errInvalidGeodataVarintLength, got %v", err)
	}

	// Ten bytes is still a valid varint length encoding.
	ten := append([]byte{10}, bytes.Repeat([]byte{0x80}, 9)...)
	ten = append(ten, 0x01)
	_, err = Decode(writeTemp(t, ten), "cn")
	if err == errInvalidGeodataVarintLength {
		t.Fatal("rejected a ten-byte varint")
	}
}
