package proxyproto

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestAppendRoundTrip(t *testing.T) {
	for _, tt := range []struct {
		name     string
		in, want Header
		wire     string // v1 only
	}{
		{
			name: "v1 tcp4",
			in:   Header{Version: 1, Source: netip.MustParseAddrPort("192.0.2.1:5000"), Destination: netip.MustParseAddrPort("198.51.100.2:443")},
			want: Header{Version: 1, Source: netip.MustParseAddrPort("192.0.2.1:5000"), Destination: netip.MustParseAddrPort("198.51.100.2:443")},
			wire: "PROXY TCP4 192.0.2.1 198.51.100.2 5000 443\r\n",
		},
		{
			name: "v1 mapped is tcp4",
			in:   Header{Version: 1, Source: netip.MustParseAddrPort("[::ffff:192.0.2.1]:5000"), Destination: netip.MustParseAddrPort("198.51.100.2:443")},
			want: Header{Version: 1, Source: netip.MustParseAddrPort("192.0.2.1:5000"), Destination: netip.MustParseAddrPort("198.51.100.2:443")},
			wire: "PROXY TCP4 192.0.2.1 198.51.100.2 5000 443\r\n",
		},
		{
			name: "v1 tcp6 with zone and a mixed pair",
			in:   Header{Version: 1, Source: netip.MustParseAddrPort("[fe80::1%eth0]:5000"), Destination: netip.MustParseAddrPort("198.51.100.2:443")},
			want: Header{Version: 1, Source: netip.MustParseAddrPort("[fe80::1]:5000"), Destination: netip.MustParseAddrPort("[::ffff:198.51.100.2]:443")},
			wire: "PROXY TCP6 fe80::1 ::ffff:198.51.100.2 5000 443\r\n",
		},
		{
			name: "v1 unknown",
			in:   Header{Version: 1},
			want: Header{Version: 1, Local: true},
			wire: "PROXY UNKNOWN\r\n",
		},
		{
			name: "v2 tcp4",
			in:   Header{Version: 2, Source: netip.MustParseAddrPort("192.0.2.1:5000"), Destination: netip.MustParseAddrPort("198.51.100.2:443")},
			want: Header{Version: 2, Source: netip.MustParseAddrPort("192.0.2.1:5000"), Destination: netip.MustParseAddrPort("198.51.100.2:443")},
		},
		{
			name: "v2 tcp6",
			in:   Header{Version: 2, Source: netip.MustParseAddrPort("[2001:db8::1]:5000"), Destination: netip.MustParseAddrPort("[2001:db8::2]:443")},
			want: Header{Version: 2, Source: netip.MustParseAddrPort("[2001:db8::1]:5000"), Destination: netip.MustParseAddrPort("[2001:db8::2]:443")},
		},
		{
			name: "v2 local",
			in:   Header{Version: 2, Local: true, Source: netip.MustParseAddrPort("192.0.2.1:5000")},
			want: Header{Version: 2, Local: true},
		},
		{
			name: "v2 unknown address",
			in:   Header{Version: 2},
			want: Header{Version: 2, Local: true},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.in.Append([]byte("x"))
			if err != nil {
				t.Fatal(err)
			}
			if b[0] != 'x' {
				t.Fatal("Append overwrote the prefix")
			}
			b = b[1:]
			if tt.wire != "" && string(b) != tt.wire {
				t.Fatalf("wire %q, want %q", b, tt.wire)
			}
			r := bytes.NewReader(append(b, "tail"...))
			got, err := Read(r)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("read %+v, want %+v", got, tt.want)
			}
			if r.Len() != len("tail") {
				t.Fatalf("%d bytes left after the header, want 4", r.Len())
			}
		})
	}
}

func TestAppendV2Bytes(t *testing.T) {
	b, err := Header{Version: 2, Source: netip.MustParseAddrPort("192.0.2.1:256"), Destination: netip.MustParseAddrPort("198.51.100.2:443")}.Append(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte{}, v2Signature...), 0x21, 0x11, 0, 12, 192, 0, 2, 1, 198, 51, 100, 2, 1, 0, 1, 187)
	if !bytes.Equal(b, want) {
		t.Fatalf("got % x\nwant % x", b, want)
	}
}

func TestAppendBadVersion(t *testing.T) {
	if _, err := (Header{Version: 3}).Append(nil); err == nil {
		t.Fatal("version 3 accepted")
	}
}
