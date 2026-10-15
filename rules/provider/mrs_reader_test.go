package provider

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// craftMrs builds a zstd-compressed MRS stream from raw header fields and a
// body, so headers no writer would produce can be tested.
func craftMrs(t *testing.T, behavior byte, count, extraLength int64, body []byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	raw.Write(MrsMagicBytes[:])
	raw.WriteByte(behavior)
	_ = binary.Write(&raw, binary.BigEndian, count)
	_ = binary.Write(&raw, binary.BigEndian, extraLength)
	raw.Write(body)

	var out bytes.Buffer
	zw, err := zstd.NewWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestMrsParseRejectsCraftedHeaders(t *testing.T) {
	strategy := NewDomainStrategy()
	behavior := strategy.Behavior().Byte()

	tests := []struct {
		name        string
		count       int64
		extraLength int64
		body        []byte
		wantErr     string
	}{
		{"huge extra length", 1, 1 << 40, nil, "extra length"},
		{"extra just over cap", 1, maxMrsExtraLength + 1, nil, "extra length"},
		{"negative extra length", 1, -1, nil, "extra length"},
		{"negative count", -1, 0, nil, "rule count"},
		{"huge count", 1 << 40, 0, nil, "rule count"},
		// domain set claiming 2^28 leaves (2 GiB if allocated up front) but
		// carrying none: must fail on the missing data, not allocate.
		{"huge domain set length", 1, 0, append([]byte{1}, be64(1<<28)...), "EOF"},
		{"domain set length over cap", 1, 0, append([]byte{1}, be64(1<<40)...), "length"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := craftMrs(t, behavior, tt.count, tt.extraLength, tt.body)
			_, err := rulesMrsParse(buf, NewDomainStrategy())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestMrsParseIPCidrHugeLength(t *testing.T) {
	strategy := NewIPCidrStrategy()
	behavior := strategy.Behavior().Byte()
	for _, length := range []int64{1 << 26, 1 << 40} {
		buf := craftMrs(t, behavior, 1, 0, append([]byte{1}, be64(length)...))
		if _, err := rulesMrsParse(buf, NewIPCidrStrategy()); err == nil {
			t.Fatalf("length %d: want error", length)
		}
	}
}

func TestMrsParseRoundTrip(t *testing.T) {
	src := NewDomainStrategy()
	for _, d := range []string{"example.com", "+.example.org"} {
		src.Insert(d)
	}
	src.FinishInsert()

	var raw bytes.Buffer
	raw.Write(MrsMagicBytes[:])
	raw.WriteByte(src.Behavior().Byte())
	_ = binary.Write(&raw, binary.BigEndian, int64(src.Count()))
	_ = binary.Write(&raw, binary.BigEndian, int64(0))
	if err := src.WriteMrs(&raw); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	zw, _ := zstd.NewWriter(&out)
	_, _ = zw.Write(raw.Bytes())
	_ = zw.Close()

	parsed, err := rulesMrsParse(out.Bytes(), NewDomainStrategy())
	if err != nil {
		t.Fatalf("valid MRS: %v", err)
	}
	if parsed.Count() != src.Count() {
		t.Fatalf("count %d, want %d", parsed.Count(), src.Count())
	}
}

func be64(v int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}
