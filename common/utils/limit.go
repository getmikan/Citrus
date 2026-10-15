package utils

import (
	"fmt"
	"io"
)

// SizeLimitError reports that a stream carried more than Limit bytes.
type SizeLimitError struct {
	Limit int64
}

func (e *SizeLimitError) Error() string {
	return fmt.Sprintf("larger than %d bytes", e.Limit)
}

// ReadAllLimit reads r until EOF like io.ReadAll, but fails with a
// *SizeLimitError once more than limit bytes are available instead of
// buffering an unbounded stream. A negative limit disables the check.
//
// One extra byte is read past the limit so that a body of exactly limit bytes
// is accepted while anything larger is reported rather than silently truncated.
func ReadAllLimit(r io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return io.ReadAll(r)
	}
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > limit {
		return nil, &SizeLimitError{Limit: limit}
	}
	return buf, nil
}

// CopyLimit copies from src to dst like io.Copy, but fails with a
// *SizeLimitError when src holds more than limit bytes. At most limit+1 bytes
// are written to dst before the error is returned. A negative limit disables
// the check.
func CopyLimit(dst io.Writer, src io.Reader, limit int64) (int64, error) {
	if limit < 0 {
		return io.Copy(dst, src)
	}
	n, err := io.Copy(dst, io.LimitReader(src, limit+1))
	if err != nil {
		return n, err
	}
	if n > limit {
		return n, &SizeLimitError{Limit: limit}
	}
	return n, nil
}
