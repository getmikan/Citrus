package trie

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func binHeader(lengths ...int64) []byte {
	var buf bytes.Buffer
	buf.WriteByte(1) // version
	for i, l := range lengths {
		_ = binary.Write(&buf, binary.BigEndian, l)
		if i < len(lengths)-1 {
			// one element worth of data for every field but the last
			_ = binary.Write(&buf, binary.BigEndian, uint64(0))
		}
	}
	return buf.Bytes()
}

func TestReadDomainSetBinBoundsLengths(t *testing.T) {
	tests := map[string][]byte{
		// claimed lengths far beyond the data present must fail on EOF
		// without allocating what the header claims
		"leaves at cap":       binHeader(MaxBinLength),
		"labelBitmap at cap":  binHeader(1, MaxBinLength),
		"labels at cap":       binHeader(1, 1, MaxBinLength),
		"leaves over cap":     binHeader(MaxBinLength + 1),
		"labels over cap":     binHeader(1, 1, 1<<40),
		"negative labels len": binHeader(1, 1, -1),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadDomainSetBin(bytes.NewReader(data)); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestReadDomainMapBinBoundsValues(t *testing.T) {
	var builder DomainSetBuilder
	if err := builder.Insert("example.com"); err != nil {
		t.Fatal(err)
	}
	set := builder.Build()
	var buf bytes.Buffer
	if err := set.WriteBin(&buf); err != nil {
		t.Fatal(err)
	}
	buf.Write([]byte{0, 1}) // separator, version
	_ = binary.Write(&buf, binary.BigEndian, int64(MaxBinLength))
	_, err := ReadDomainMapBin(bytes.NewReader(buf.Bytes()), func(r io.Reader) (byte, error) {
		var b [1]byte
		_, err := io.ReadFull(r, b[:])
		return b[0], err
	})
	if err == nil {
		t.Fatal("want error for values length beyond the data")
	}
}
