package memconservative

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

var (
	errFailedToReadBytes            = errors.New("failed to read bytes")
	errFailedToReadExpectedLenBytes = errors.New("failed to read expected length of bytes")
	errInvalidGeodataFile           = errors.New("invalid geodata file")
	errInvalidGeodataVarintLength   = errors.New("invalid geodata varint length")
	errInvalidGeodataRecordLength   = errors.New("invalid geodata record length")
	errCodeNotFound                 = errors.New("code not found")
)

// maxGeodataRecordSize caps a single GeoIP/GeoSite record (one country or
// category). The largest real records are a few MiB; together with the
// check against the file size this keeps a corrupt or crafted varint length
// from turning into a huge allocation.
const maxGeodataRecordSize = 128 << 20

// maxVarintLen is the longest protobuf varint (binary.MaxVarintLen64).
const maxVarintLen = 10

func emitBytes(f io.ReadSeeker, code string) ([]byte, error) {
	// The file size bounds every length below: no record can be longer than
	// the file that holds it.
	fileSize, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, errFailedToReadBytes
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, errFailedToReadBytes
	}
	maxRecord := uint64(fileSize)
	if maxRecord > maxGeodataRecordSize {
		maxRecord = maxGeodataRecordSize
	}

	reader := bufio.NewReaderSize(f, 16*1024)
	readError := func(err error) error {
		switch err {
		case io.EOF:
			return errCodeNotFound
		case io.ErrUnexpectedEOF:
			return errFailedToReadExpectedLenBytes
		default:
			return errFailedToReadBytes
		}
	}
	var lengthBytes []byte
	readLength := func() (uint64, error) {
		lengthBytes = lengthBytes[:0]
		for {
			b, err := reader.ReadByte()
			if err != nil {
				return 0, readError(err)
			}
			lengthBytes = append(lengthBytes, b)
			if b >= 128 && len(lengthBytes) >= maxVarintLen {
				// a protobuf varint never needs more than ten bytes
				return 0, errInvalidGeodataVarintLength
			}
			if b < 128 {
				n, size := protowire.ConsumeVarint(lengthBytes)
				if size < 0 {
					return 0, errInvalidGeodataVarintLength
				}
				return n, nil
			}
		}
	}
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, readError(err)
		}
		if b != 10 {
			return nil, errInvalidGeodataFile
		}
		length, err := readLength()
		if err != nil {
			return nil, err
		}
		if length > maxRecord {
			return nil, errInvalidGeodataRecordLength
		}
		b, err = reader.ReadByte()
		if err != nil {
			return nil, readError(err)
		}
		if b != 10 {
			return nil, errInvalidGeodataFile
		}
		codeLength, err := readLength()
		if err != nil {
			return nil, err
		}
		// the code field (tag, varint length, name) must fit in the record;
		// this also keeps the skip offset below from going negative
		if codeLength > length || 1+uint64(len(lengthBytes))+codeLength > length {
			return nil, errInvalidGeodataRecordLength
		}
		name := make([]byte, codeLength)
		if _, err := io.ReadFull(reader, name); err != nil {
			return nil, readError(err)
		}
		prefixLength := 1 + uint64(len(lengthBytes)) + codeLength
		if strings.EqualFold(string(name), code) {
			result := make([]byte, length)
			n := copy(result, []byte{10})
			n += copy(result[n:], lengthBytes)
			n += copy(result[n:], name)
			if _, err := io.ReadFull(reader, result[n:]); err != nil {
				if err == io.EOF {
					return nil, errFailedToReadExpectedLenBytes
				}
				return nil, readError(err)
			}
			return result, nil
		}
		offset := int64(length) - int64(prefixLength)
		if offset >= 0 && offset <= int64(reader.Buffered()) {
			_, err = reader.Discard(int(offset))
		} else {
			_, err = f.Seek(offset-int64(reader.Buffered()), io.SeekCurrent)
			reader.Reset(f)
		}
		if err != nil {
			return nil, errFailedToReadBytes
		}
	}
}

func Decode(filename, code string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %s, base error: %s", filename, err.Error())
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	geoBytes, err := emitBytes(f, code)
	if err != nil {
		return nil, err
	}
	return geoBytes, nil
}
