package utils

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestReadAllLimit(t *testing.T) {
	buf, err := ReadAllLimit(strings.NewReader("12345"), 5)
	if err != nil || string(buf) != "12345" {
		t.Fatalf("exact limit: %q %v", buf, err)
	}
	_, err = ReadAllLimit(strings.NewReader("123456"), 5)
	var limitErr *SizeLimitError
	if !errors.As(err, &limitErr) || limitErr.Limit != 5 {
		t.Fatalf("over limit: %v", err)
	}
	buf, err = ReadAllLimit(strings.NewReader("123456"), -1)
	if err != nil || len(buf) != 6 {
		t.Fatalf("unlimited: %q %v", buf, err)
	}
}

func TestCopyLimit(t *testing.T) {
	var dst bytes.Buffer
	n, err := CopyLimit(&dst, strings.NewReader("12345"), 5)
	if err != nil || n != 5 {
		t.Fatalf("exact limit: %d %v", n, err)
	}
	dst.Reset()
	_, err = CopyLimit(&dst, strings.NewReader("123456"), 5)
	var limitErr *SizeLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("over limit: %v", err)
	}
	if dst.Len() > 6 {
		t.Fatalf("wrote %d bytes past a 5-byte limit", dst.Len())
	}
}

func TestLimitMaxInt64IsUnlimited(t *testing.T) {
	buf, err := ReadAllLimit(strings.NewReader("12345"), math.MaxInt64)
	if err != nil || string(buf) != "12345" {
		t.Fatalf("ReadAllLimit: %q %v", buf, err)
	}
	var dst bytes.Buffer
	n, err := CopyLimit(&dst, strings.NewReader("12345"), math.MaxInt64)
	if err != nil || n != 5 || dst.String() != "12345" {
		t.Fatalf("CopyLimit: %d %q %v", n, dst.String(), err)
	}
}
