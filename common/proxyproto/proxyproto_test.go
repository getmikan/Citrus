package proxyproto

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// v2Header builds a v2 header: command and family/protocol bytes, then the
// payload with its length.
func v2Header(command, famProto byte, payload []byte) []byte {
	b := append([]byte{}, v2Signature...)
	b = append(b, 0x20|command, famProto)
	b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))
	return append(b, payload...)
}

func v2Addrs(src, dst string, sport, dport uint16) []byte {
	s, d := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	b := append(s.AsSlice(), d.AsSlice()...)
	b = binary.BigEndian.AppendUint16(b, sport)
	return binary.BigEndian.AppendUint16(b, dport)
}

func TestReadV1(t *testing.T) {
	tests := []struct {
		name string
		line string
		want Header
	}{
		{"tcp4", "PROXY TCP4 203.0.113.7 192.0.2.1 51234 443\r\n", Header{
			Version: 1, Source: netip.MustParseAddrPort("203.0.113.7:51234"), Destination: netip.MustParseAddrPort("192.0.2.1:443")}},
		{"tcp6", "PROXY TCP6 2001:db8::7 2001:db8::1 51234 443\r\n", Header{
			Version: 1, Source: netip.MustParseAddrPort("[2001:db8::7]:51234"), Destination: netip.MustParseAddrPort("[2001:db8::1]:443")}},
		{"unknown", "PROXY UNKNOWN\r\n", Header{Version: 1, Local: true}},
		{"unknown with the rest of the line", "PROXY UNKNOWN ffff::ffff ::1 65535 65535\r\n", Header{Version: 1, Local: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rest := "rest of the stream"
			r := strings.NewReader(tt.line + rest)
			got, err := Read(r)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			left, _ := io.ReadAll(r)
			assert.Equal(t, rest, string(left), "nothing past the header is consumed")
		})
	}
}

func TestReadV1Malformed(t *testing.T) {
	longest := "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n"
	require.LessOrEqual(t, len(longest), maxV1Length, "the longest legal line fits")
	_, err := Read(strings.NewReader(longest))
	require.NoError(t, err)

	tests := []struct {
		name string
		line string
		want error
	}{
		{"line too long", "PROXY TCP4 " + strings.Repeat("1", 200) + "\r\n", ErrTooLong},
		{"no line end within the limit", "PROXY TCP4 1.2.3.4 5.6.7.8 1 2" + strings.Repeat(" ", 100), ErrTooLong},
		{"LF without CR", "PROXY TCP4 203.0.113.7 192.0.2.1 51234 443\n", ErrMalformed},
		{"unknown protocol", "PROXY UDP4 203.0.113.7 192.0.2.1 51234 443\r\n", ErrMalformed},
		{"too few fields", "PROXY TCP4 203.0.113.7 192.0.2.1 51234\r\n", ErrMalformed},
		{"too many fields", "PROXY TCP4 203.0.113.7 192.0.2.1 51234 443 1\r\n", ErrMalformed},
		{"double space", "PROXY TCP4  203.0.113.7 192.0.2.1 51234 443\r\n", ErrMalformed},
		{"v6 address in TCP4", "PROXY TCP4 2001:db8::7 192.0.2.1 51234 443\r\n", ErrMalformed},
		{"v4 address in TCP6", "PROXY TCP6 203.0.113.7 2001:db8::1 51234 443\r\n", ErrMalformed},
		{"zoned address", "PROXY TCP6 fe80::1%eth0 2001:db8::1 51234 443\r\n", ErrMalformed},
		{"bad address", "PROXY TCP4 203.0.113.256 192.0.2.1 51234 443\r\n", ErrMalformed},
		{"port out of range", "PROXY TCP4 203.0.113.7 192.0.2.1 65536 443\r\n", ErrMalformed},
		{"negative port", "PROXY TCP4 203.0.113.7 192.0.2.1 -1 443\r\n", ErrMalformed},
		{"truncated", "PROXY TCP4 203.0.113.7 192.0.2.1 512", ErrTruncated},
		{"truncated in the signature", "PROXY TCP", ErrTruncated},
		{"empty", "", ErrTruncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Read(strings.NewReader(tt.line))
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestReadV2(t *testing.T) {
	tlv := []byte{0x04, 0x00, 0x03, 'a', 'b', 'c'} // NOOP with 3 bytes of value
	tests := []struct {
		name string
		data []byte
		want Header
	}{
		{"tcp4", v2Header(1, 0x11, v2Addrs("203.0.113.7", "192.0.2.1", 51234, 443)), Header{
			Version: 2, Source: netip.MustParseAddrPort("203.0.113.7:51234"), Destination: netip.MustParseAddrPort("192.0.2.1:443")}},
		{"tcp6", v2Header(1, 0x21, v2Addrs("2001:db8::7", "2001:db8::1", 51234, 443)), Header{
			Version: 2, Source: netip.MustParseAddrPort("[2001:db8::7]:51234"), Destination: netip.MustParseAddrPort("[2001:db8::1]:443")}},
		{"tcp4 with TLVs", v2Header(1, 0x11, append(v2Addrs("203.0.113.7", "192.0.2.1", 51234, 443), tlv...)), Header{
			Version: 2, Source: netip.MustParseAddrPort("203.0.113.7:51234"), Destination: netip.MustParseAddrPort("192.0.2.1:443")}},
		{"local", v2Header(0, 0x00, nil), Header{Version: 2, Local: true}},
		{"local with addresses and TLVs", v2Header(0, 0x11, append(v2Addrs("203.0.113.7", "192.0.2.1", 1, 2), tlv...)), Header{Version: 2, Local: true}},
		{"proxy with an unspecified family", v2Header(1, 0x00, nil), Header{Version: 2, Local: true}},
		{"proxy with unix addresses", v2Header(1, 0x31, make([]byte, 216)), Header{Version: 2, Local: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rest := "\x16\x03\x01 client hello"
			r := bytes.NewReader(append(append([]byte{}, tt.data...), rest...))
			got, err := Read(r)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			left, _ := io.ReadAll(r)
			assert.Equal(t, rest, string(left), "nothing past the header is consumed")
		})
	}
}

func TestReadV2Malformed(t *testing.T) {
	good := v2Header(1, 0x11, v2Addrs("203.0.113.7", "192.0.2.1", 51234, 443))
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"wrong version", append(append(append([]byte{}, v2Signature...), 0x31, 0x11, 0, 12), v2Addrs("1.1.1.1", "2.2.2.2", 1, 2)...), ErrMalformed},
		{"unknown command", v2Header(2, 0x11, v2Addrs("1.1.1.1", "2.2.2.2", 1, 2)), ErrMalformed},
		{"unknown family", v2Header(1, 0x41, make([]byte, 12)), ErrMalformed},
		{"udp over tcp", v2Header(1, 0x12, v2Addrs("1.1.1.1", "2.2.2.2", 1, 2)), ErrMalformed},
		{"unspecified protocol", v2Header(1, 0x10, v2Addrs("1.1.1.1", "2.2.2.2", 1, 2)), ErrMalformed},
		{"address block too short for tcp4", v2Header(1, 0x11, make([]byte, 11)), ErrMalformed},
		{"address block too short for tcp6", v2Header(1, 0x21, make([]byte, 35)), ErrMalformed},
		{"v2 length over the limit", v2Header(1, 0x11, make([]byte, MaxV2Length+1)), ErrTooLong},
		{"length of 65535", append(append([]byte{}, v2Signature...), 0x21, 0x11, 0xff, 0xff), ErrTooLong},
		{"truncated payload", good[:len(good)-1], ErrTruncated},
		{"truncated before the length", good[:v2SigLength+2], ErrTruncated},
		{"truncated signature", good[:8], ErrTruncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Read(bytes.NewReader(tt.data))
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestReadNoHeader(t *testing.T) {
	for name, data := range map[string]string{
		"tls client hello":        "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03abcdefgh",
		"http":                    "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"proxy without a space":   "PROXYTCP4 1.2.3.4 5.6.7.8 1 2\r\n",
		"almost the v2 signature": "\r\n\r\n\x00\r\nQUIT\x00\x21\x11\x00\x0c",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Read(strings.NewReader(data))
			assert.ErrorIs(t, err, ErrNoHeader)
		})
	}
}
