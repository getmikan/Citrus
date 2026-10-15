package cidr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"go4.org/netipx"
)

const (
	// MaxBinLength bounds the range count stored in a binary IpCidrSet. Full
	// country/ASN lists hold well under a million ranges; the cap only keeps
	// a corrupt or hostile int64 header from reaching make.
	MaxBinLength = 1 << 26

	// binPreallocLength is how many ranges are allocated up front; the slice
	// grows as ranges are actually read, so memory follows the data present
	// rather than the length the header claims.
	binPreallocLength = 1 << 14
)

func (ss *IpCidrSet) WriteBin(w io.Writer) (err error) {
	// version
	_, err = w.Write([]byte{1})
	if err != nil {
		return err
	}

	// rr
	err = binary.Write(w, binary.BigEndian, int64(len(ss.rr)))
	if err != nil {
		return err
	}
	for _, r := range ss.rr {
		err = binary.Write(w, binary.BigEndian, r.From().As16())
		if err != nil {
			return err
		}
		err = binary.Write(w, binary.BigEndian, r.To().As16())
		if err != nil {
			return err
		}
	}

	return nil
}

func ReadIpCidrSet(r io.Reader) (ss *IpCidrSet, err error) {
	// version
	version := make([]byte, 1)
	_, err = io.ReadFull(r, version)
	if err != nil {
		return nil, err
	}
	if version[0] != 1 {
		return nil, errors.New("version is invalid")
	}

	ss = NewIpCidrSet()
	var length int64

	// rr
	err = binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if length < 1 || length > MaxBinLength {
		return nil, fmt.Errorf("length %d is invalid", length)
	}
	prealloc := length
	if prealloc > binPreallocLength {
		prealloc = binPreallocLength
	}
	ss.rr = make([]netipx.IPRange, 0, prealloc)
	for i := int64(0); i < length; i++ {
		var a16 [16]byte
		err = binary.Read(r, binary.BigEndian, &a16)
		if err != nil {
			return nil, err
		}
		from := netip.AddrFrom16(a16).Unmap()
		err = binary.Read(r, binary.BigEndian, &a16)
		if err != nil {
			return nil, err
		}
		to := netip.AddrFrom16(a16).Unmap()
		ss.rr = append(ss.rr, netipx.IPRangeFrom(from, to))
	}

	return ss, nil
}
