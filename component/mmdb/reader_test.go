package mmdb

import (
	"bytes"
	"net"
	"testing"

	"github.com/oschwald/maxminddb-golang"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mmdbString encodes a short (< 29 bytes) UTF-8 string in the MaxMind DB data format.
func mmdbString(s string) []byte {
	return append([]byte{0x40 | byte(len(s))}, s...)
}

// buildTestMMDB builds a minimal IPv4 database with a single search-tree node:
// 0.0.0.0/1 has no record, 128.0.0.0/1 points at the given data (a pre-encoded value).
func buildTestMMDB(t *testing.T, databaseType string, data []byte) *maxminddb.Reader {
	t.Helper()
	var b bytes.Buffer
	// search tree: node_count = 1, record_size = 24
	b.Write([]byte{0x00, 0x00, 0x01}) // left: == node_count, no data
	b.Write([]byte{0x00, 0x00, 0x11}) // right: node_count + 16 + offset 0
	b.Write(make([]byte, 16))         // data section separator
	b.Write(data)
	b.WriteString("\xAB\xCD\xEFMaxMind.com")
	b.WriteByte(0xE0 | 6) // map with 6 entries
	b.Write(mmdbString("node_count"))
	b.Write([]byte{0xC1, 0x01})
	b.Write(mmdbString("record_size"))
	b.Write([]byte{0xA1, 24})
	b.Write(mmdbString("ip_version"))
	b.Write([]byte{0xA1, 4})
	b.Write(mmdbString("database_type"))
	b.Write(mmdbString(databaseType))
	b.Write(mmdbString("binary_format_major_version"))
	b.Write([]byte{0xA1, 2})
	b.Write(mmdbString("binary_format_minor_version"))
	b.Write([]byte{0xA0})

	reader, err := maxminddb.FromBytes(b.Bytes())
	require.NoError(t, err)
	return reader
}

func TestLookupASNIPInfo(t *testing.T) {
	var data []byte
	data = append(data, 0xE0|2)
	data = append(data, mmdbString("asn")...)
	data = append(data, mmdbString("AS13335")...)
	data = append(data, mmdbString("name")...)
	data = append(data, mmdbString("Cloudflare")...)
	r := ASNReader{Reader: buildTestMMDB(t, "ipinfo generic_asn_free.mmdb", data)}

	asn, name := r.LookupASN(net.ParseIP("200.1.1.1"))
	assert.Equal(t, "13335", asn)
	assert.Equal(t, "Cloudflare", name)

	// an IP with no record in the database is "not found", not a panic
	assert.NotPanics(t, func() {
		asn, name = r.LookupASN(net.ParseIP("1.1.1.1"))
	})
	assert.Equal(t, "", asn)
	assert.Equal(t, "", name)
}

func TestLookupASNGeoLite2Missing(t *testing.T) {
	var data []byte
	data = append(data, 0xE0|1)
	data = append(data, mmdbString("autonomous_system_number")...)
	data = append(data, 0xC2, 0x34, 0x17) // uint32 13335
	r := ASNReader{Reader: buildTestMMDB(t, "GeoLite2-ASN", data)}

	asn, _ := r.LookupASN(net.ParseIP("200.1.1.1"))
	assert.Equal(t, "13335", asn)
	assert.NotPanics(t, func() { r.LookupASN(net.ParseIP("1.1.1.1")) })
}

func TestLookupCodeMetaV0(t *testing.T) {
	var data []byte
	data = append(data, 0x02, 0x04) // array (extended type 11) of 2 entries
	data = append(data, mmdbString("cn")...)
	data = append(data, 0xA1, 0x07) // a non-string item is skipped
	r := IPReader{Reader: buildTestMMDB(t, "Meta-geoip0", data), databaseType: typeMetaV0}

	var codes []string
	assert.NotPanics(t, func() { codes = r.LookupCode(net.ParseIP("200.1.1.1")) })
	assert.Equal(t, []string{"cn"}, codes)
	assert.Empty(t, r.LookupCode(net.ParseIP("1.1.1.1")))
}
