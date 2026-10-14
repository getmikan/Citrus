package vless

import (
	"bytes"
	"strconv"
	"testing"

	"google.golang.org/protobuf/proto"
)

// A LEN field declaring more bytes than the input holds must fail before the
// declared size is allocated (a huge varint used to reach make directly).
func TestReadAddonsRejectsLengthBeyondInput(t *testing.T) {
	for _, n := range []uint64{4, 1 << 40, 1<<63 - 1, 1<<64 - 1} {
		var b bytes.Buffer
		WriteUvarint(&b, (2<<3)|2)
		WriteUvarint(&b, n)
		b.WriteString("abc")
		if _, err := ReadAddons(b.Bytes()); err == nil {
			t.Fatalf("length %d over a 3-byte body accepted", n)
		}
	}
}

func TestAddons(t *testing.T) {
	var tests = []struct {
		flow string
		seed []byte
	}{
		{XRV, nil},
		{XRS, []byte{1, 2, 3}},
		{"", []byte{1, 2, 3}},
		{"", nil},
	}

	for i, test := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Run("proto->handwritten", func(t *testing.T) {
				addons := new(Addons)
				addons.Flow = test.flow
				addons.Seed = test.seed

				addonsBytes, err := proto.Marshal(addons)
				if err != nil {
					t.Errorf("error marshalling addons: %v", err)
					return
				}
				addons, err = ReadAddons(addonsBytes)
				if err != nil {
					t.Errorf("error reading addons: %v", err)
					return
				}

				if addons.Flow != test.flow {
					t.Errorf("got %v; want %v", addons.Flow, test.flow)
					return
				}
				if !bytes.Equal(addons.Seed, test.seed) {
					t.Errorf("got %v; want %v", addons.Seed, test.seed)
					return
				}
			})

			t.Run("handwritten->proto", func(t *testing.T) {
				addons := new(Addons)
				addons.Flow = test.flow
				addons.Seed = test.seed

				addonsBytes := WriteAddons(addons)
				err := proto.Unmarshal(addonsBytes, addons)
				if err != nil {
					t.Errorf("error reading addons: %v", err)
					return
				}

				if addons.Flow != test.flow {
					t.Errorf("got %v; want %v", addons.Flow, test.flow)
					return
				}
				if !bytes.Equal(addons.Seed, test.seed) {
					t.Errorf("got %v; want %v", addons.Seed, test.seed)
					return
				}
			})

			t.Run("handwritten->handwritten", func(t *testing.T) {
				addons := new(Addons)
				addons.Flow = test.flow
				addons.Seed = test.seed

				addonsBytes := WriteAddons(addons)
				addons, err := ReadAddons(addonsBytes)
				if err != nil {
					t.Errorf("error reading addons: %v", err)
					return
				}

				if addons.Flow != test.flow {
					t.Errorf("got %v; want %v", addons.Flow, test.flow)
					return
				}
				if !bytes.Equal(addons.Seed, test.seed) {
					t.Errorf("got %v; want %v", addons.Seed, test.seed)
					return
				}
			})
		})
	}
}
