package encryption

import (
	"errors"
	"testing"
)

func TestDecodeHeaderLength(t *testing.T) {
	for _, tt := range []struct {
		l  int
		ok bool
	}{
		{16, false},
		{17, true},
		{5 + 8192 + 16, true},
		{16640, true}, // TLS 1.3 max record: 16384 + 256
		{16641, false},
		{17000, false},
	} {
		h := make([]byte, 5)
		EncodeHeader(h, tt.l)
		l, err := DecodeHeader(h)
		if tt.ok != (err == nil) {
			t.Errorf("DecodeHeader(%d): err = %v, want ok = %v", tt.l, err, tt.ok)
		}
		if err != nil && !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("DecodeHeader(%d): unexpected error %v", tt.l, err)
		}
		if l != tt.l {
			t.Errorf("DecodeHeader(%d): l = %d", tt.l, l)
		}
	}
	if _, err := DecodeHeader([]byte{22, 3, 3, 0, 32}); err == nil {
		t.Error("DecodeHeader accepted a non application-data record")
	}
}
