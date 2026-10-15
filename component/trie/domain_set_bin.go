package trie

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// MaxBinLength bounds every element count stored in a binary DomainSet
	// or DomainMap. The largest real-world rule sets (a few million domains)
	// stay far below it; it only exists so a corrupt or hostile int64 header
	// cannot be fed straight into make.
	MaxBinLength = 1 << 28

	// binPreallocLength is how many elements are allocated up front for a
	// length read from the stream. Larger slices grow while their elements
	// are actually read, so memory follows the data present rather than the
	// length the header claims.
	binPreallocLength = 1 << 16
)

// checkBinLength validates a length read from a binary header.
func checkBinLength(length int64) error {
	if length < 1 || length > MaxBinLength {
		return fmt.Errorf("length %d is invalid", length)
	}
	return nil
}

func readBinUint64s(r io.Reader, length int64) ([]uint64, error) {
	out := make([]uint64, 0, min64(length, binPreallocLength))
	for i := int64(0); i < length; i++ {
		var v uint64
		if err := binary.Read(r, binary.BigEndian, &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func readBinBytes(r io.Reader, length int64) ([]byte, error) {
	out := make([]byte, 0, min64(length, binPreallocLength))
	chunk := make([]byte, min64(length, binPreallocLength))
	for left := length; left > 0; {
		n := min64(left, int64(len(chunk)))
		if _, err := io.ReadFull(r, chunk[:n]); err != nil {
			return nil, err
		}
		out = append(out, chunk[:n]...)
		left -= n
	}
	return out, nil
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func (ss *DomainSet) WriteBin(w io.Writer) (err error) {
	// version
	_, err = w.Write([]byte{1})
	if err != nil {
		return err
	}

	// leaves
	err = binary.Write(w, binary.BigEndian, int64(len(ss.leaves)))
	if err != nil {
		return err
	}
	for _, d := range ss.leaves {
		err = binary.Write(w, binary.BigEndian, d)
		if err != nil {
			return err
		}
	}

	// labelBitmap
	err = binary.Write(w, binary.BigEndian, int64(len(ss.labelBitmap)))
	if err != nil {
		return err
	}
	for _, d := range ss.labelBitmap {
		err = binary.Write(w, binary.BigEndian, d)
		if err != nil {
			return err
		}
	}

	// labels
	err = binary.Write(w, binary.BigEndian, int64(len(ss.labels)))
	if err != nil {
		return err
	}
	_, err = w.Write(ss.labels)
	if err != nil {
		return err
	}

	return nil
}

func ReadDomainSetBin(r io.Reader) (ds *DomainSet, err error) {
	// version
	version := make([]byte, 1)
	_, err = io.ReadFull(r, version)
	if err != nil {
		return nil, err
	}
	if version[0] != 1 {
		return nil, errors.New("version is invalid")
	}

	ds = &DomainSet{}
	var length int64

	// leaves
	err = binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if err = checkBinLength(length); err != nil {
		return nil, err
	}
	ds.leaves, err = readBinUint64s(r, length)
	if err != nil {
		return nil, err
	}

	// labelBitmap
	err = binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if err = checkBinLength(length); err != nil {
		return nil, err
	}
	ds.labelBitmap, err = readBinUint64s(r, length)
	if err != nil {
		return nil, err
	}

	// labels
	err = binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if err = checkBinLength(length); err != nil {
		return nil, err
	}
	ds.labels, err = readBinBytes(r, length)
	if err != nil {
		return nil, err
	}

	ds.init()
	return ds, nil
}
