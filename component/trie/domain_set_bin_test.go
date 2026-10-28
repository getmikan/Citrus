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

// rawDomainSetBin encodes the three DomainSet fields without validation, so
// tests can feed ReadDomainSetBin a structurally broken trie.
func rawDomainSetBin(leaves, labelBitmap []uint64, labels string) []byte {
	var buf bytes.Buffer
	buf.WriteByte(1) // version
	_ = binary.Write(&buf, binary.BigEndian, int64(len(leaves)))
	_ = binary.Write(&buf, binary.BigEndian, leaves)
	_ = binary.Write(&buf, binary.BigEndian, int64(len(labelBitmap)))
	_ = binary.Write(&buf, binary.BigEndian, labelBitmap)
	_ = binary.Write(&buf, binary.BigEndian, int64(len(labels)))
	buf.WriteString(labels)
	return buf.Bytes()
}

func TestReadDomainSetBinRejectsMalformedTrie(t *testing.T) {
	tests := map[string][]byte{
		// no terminating 1 bit for any node: Foreach and Has used to index
		// past the end of labels
		"no node terminators": rawDomainSetBin([]uint64{1}, []uint64{0}, "a"),
		// one label but the bitmap describes two edges
		"labels shorter than edges": rawDomainSetBin([]uint64{2}, []uint64{0b1100}, "a"),
		// the root has no children, yet node 1 claims an edge to itself
		"child before parent": rawDomainSetBin([]uint64{2}, []uint64{0b101}, "a"),
		// a valid trie followed by an extra node in the padding bits
		"trailing node": rawDomainSetBin([]uint64{2}, []uint64{0b1110}, "a"),
		// a root with 64 children, but leaves only cover node ids 0..63
		"short leaves": rawDomainSetBin([]uint64{^uint64(0)}, []uint64{0, ^uint64(0), 1}, string(bytes.Repeat([]byte{'a'}, 64))),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadDomainSetBin(bytes.NewReader(data)); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestReadDomainSetBinRoundTripDeepKey(t *testing.T) {
	// A long single chain must round-trip and iterate without one stack
	// frame per byte.
	long := bytes.Repeat([]byte("abcdefghi."), 400)
	long = append(long, "com"...)
	var builder DomainSetBuilder
	for _, domain := range []string{"example.com", "+.example.org", string(long)} {
		if err := builder.Insert(domain); err != nil {
			t.Fatal(err)
		}
	}
	set := builder.Build()
	var buf bytes.Buffer
	if err := set.WriteBin(&buf); err != nil {
		t.Fatal(err)
	}
	got, err := ReadDomainSetBin(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var want, have []string
	set.Foreach(func(key string) bool { want = append(want, key); return true })
	got.Foreach(func(key string) bool { have = append(have, key); return true })
	if len(want) != 4 || len(have) != len(want) {
		t.Fatalf("keys: want %q, got %q", want, have)
	}
	for i := range want {
		if want[i] != have[i] {
			t.Fatalf("key %d: want %q, got %q", i, want[i], have[i])
		}
	}
	for _, domain := range []string{"example.com", "a.example.org", string(long)} {
		if !got.Has(domain) {
			t.Errorf("Has(%q) = false", domain)
		}
	}
}

func TestReadDomainMapBinRejectsValueCountMismatch(t *testing.T) {
	var builder DomainSetBuilder
	for _, domain := range []string{"example.com", "example.org"} {
		if err := builder.Insert(domain); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := builder.Build().WriteBin(&buf); err != nil {
		t.Fatal(err)
	}
	buf.Write([]byte{0, 1}) // separator, version
	_ = binary.Write(&buf, binary.BigEndian, int64(1))
	buf.WriteByte(7)
	_, err := ReadDomainMapBin(bytes.NewReader(buf.Bytes()), func(r io.Reader) (byte, error) {
		var b [1]byte
		_, err := io.ReadFull(r, b[:])
		return b[0], err
	})
	if err == nil {
		t.Fatal("want error for one value on two domains")
	}
}
