package provider

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/klauspost/compress/zstd"
)

var MrsMagicBytes = [4]byte{'M', 'R', 'S', 1} // MRSv1

const (
	// maxMrsDecodedSize caps how much decompressed data an MRS file may
	// carry. Real rule sets decode to a few MiB (tens for the very largest
	// domain lists), so this stops a zstd bomb without touching valid files.
	maxMrsDecodedSize = 256 << 20

	// maxMrsExtraLength caps the reserved "extra" header block, which no
	// current writer fills.
	maxMrsExtraLength = 1 << 20
)

func rulesMrsParse(buf []byte, strategy ruleStrategy) (ruleStrategy, error) {
	if _strategy, ok := strategy.(mrsRuleStrategy); ok {
		zReader, err := zstd.NewReader(bytes.NewReader(buf), zstd.WithDecoderMaxMemory(maxMrsDecodedSize))
		if err != nil {
			return nil, err
		}
		defer zReader.Close()
		// Past the cap the stream looks truncated, so readers below fail
		// with io.ErrUnexpectedEOF instead of decoding without bound.
		reader := io.LimitReader(zReader, maxMrsDecodedSize)

		// header
		var header [4]byte
		_, err = io.ReadFull(reader, header[:])
		if err != nil {
			return nil, err
		}
		if header != MrsMagicBytes {
			return nil, fmt.Errorf("invalid MrsMagic bytes")
		}

		// behavior
		var _behavior [1]byte
		_, err = io.ReadFull(reader, _behavior[:])
		if err != nil {
			return nil, err
		}
		if _behavior[0] != strategy.Behavior().Byte() {
			return nil, fmt.Errorf("invalid behavior")
		}

		// count
		var count int64
		err = binary.Read(reader, binary.BigEndian, &count)
		if err != nil {
			return nil, err
		}
		// count is only reported back (rule-set stats); keep it sane and
		// within int range on 32-bit platforms
		if count < 0 || count > math.MaxInt32 {
			return nil, fmt.Errorf("rule count %d is invalid", count)
		}

		// extra (reserved for future using)
		var length int64
		err = binary.Read(reader, binary.BigEndian, &length)
		if err != nil {
			return nil, err
		}
		if length < 0 || length > maxMrsExtraLength {
			return nil, fmt.Errorf("extra length %d is invalid", length)
		}
		if length > 0 {
			extra := make([]byte, length)
			_, err = io.ReadFull(reader, extra)
			if err != nil {
				return nil, err
			}
		}

		err = _strategy.FromMrs(reader, int(count))
		return strategy, err
	} else {
		return nil, ErrInvalidFormat
	}
}
