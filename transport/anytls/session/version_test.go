package session

import "testing"

func TestParsePeerVersion(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint32
		ok   bool
	}{
		{"2", 2, true},
		{"1", 1, true},
		{"0", 0, true},
		{"4294967295", 4294967295, true},
		{"", 0, false},
		{"-1", 0, false},
		{"4294967296", 0, false},
		{"18446744073709551617", 0, false},
		{"2x", 0, false},
	} {
		got, ok := parsePeerVersion(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("parsePeerVersion(%q) = %d, %v; want %d, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
