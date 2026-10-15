package memconservative

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/component/geodata/router"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDecodeValidFile(t *testing.T) {
	list := &router.GeoSiteList{Entry: []*router.GeoSite{
		{CountryCode: "PRIVATE", Domain: []*router.Domain{{Type: router.Domain_Full, Value: "localhost"}}},
		{CountryCode: "CN", Domain: []*router.Domain{{Type: router.Domain_Domain, Value: "example.cn"}}},
	}}
	data, err := proto.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	path := writeTemp(t, data)

	raw, err := Decode(path, "cn")
	if err != nil {
		t.Fatalf("decode cn: %v", err)
	}
	var site router.GeoSite
	if err := proto.Unmarshal(raw, &site); err != nil {
		t.Fatal(err)
	}
	if site.CountryCode != "CN" || len(site.Domain) != 1 || site.Domain[0].Value != "example.cn" {
		t.Fatalf("unexpected record: %v", &site)
	}

	if _, err := Decode(path, "missing"); err != errCodeNotFound {
		t.Fatalf("missing code: want errCodeNotFound, got %v", err)
	}
}

func TestDecodeRejectsCraftedLengths(t *testing.T) {
	record := func(length, codeLength uint64, tail int) []byte {
		b := []byte{10}
		b = protowire.AppendVarint(b, length)
		b = append(b, 10)
		b = protowire.AppendVarint(b, codeLength)
		return append(b, make([]byte, tail)...)
	}

	tests := map[string][]byte{
		// record length far beyond the file (would be a 1 TiB make)
		"record longer than file": record(1<<40, 2, 8),
		// code length larger than its record
		"code longer than record": record(4, 1<<30, 8),
		// code field just overflowing the record (tag+varint+name > length)
		"code overflows record": record(3, 2, 8),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(writeTemp(t, data), "cn")
			if err != errInvalidGeodataRecordLength {
				t.Fatalf("want errInvalidGeodataRecordLength, got %v", err)
			}
		})
	}
}
