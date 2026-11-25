package wireguard

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
)

// keySalt is the domain separation of the client key derivation. The panel
// derives the same scalar from the same slot secret (proto.WireGuardUserKey),
// so neither side ever stores a client private key: a leaked database leaks
// secrets, not the tunnel keys made of them.
const keySalt = "mikan/wg/"

// maxPool bounds the tunnel subnet: a pool is a slice of addresses in memory,
// and no node has 65 536 users on one inbound.
const maxPool = 1 << 16

// privateKey derives the client's WireGuard private key from its slot secret.
// SHA-256(keySalt+secret) with the curve25519 clamping applied is always a
// valid X25519 scalar.
func privateKey(secret string) [32]byte {
	sum := sha256.Sum256([]byte(keySalt + secret))
	sum[0] &= 248
	sum[31] &= 127
	sum[31] |= 64
	return sum
}

// UserKey is the lookup key of an inbound user: the public key of the peer
// made from the user's secret. Two users with the same secret are the same
// peer, so the key also serves as the uniqueness check of the user set.
func UserKey(secret string) (key [32]byte, err error) {
	private := privateKey(secret)
	pub, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return key, fmt.Errorf("derive public key: %w", err)
	}
	copy(key[:], pub)
	return key, nil
}

// serverKeys returns the server private key and the public key clients get in
// their config.
func serverKeys(private [32]byte) (pub [32]byte, err error) {
	p, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return pub, fmt.Errorf("derive server public key: %w", err)
	}
	if len(p) != 32 {
		return pub, errors.New("derive server public key: unexpected length")
	}
	copy(pub[:], p)
	return pub, nil
}

// parsePool validates the tunnel subnet and returns it as a prefix plus its
// first host, which belongs to the server.
func parsePool(cidr string) (prefix netip.Prefix, server netip.Addr, err error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return prefix, server, fmt.Errorf("tunnel subnet %q: %w", cidr, err)
	}
	p = p.Masked()
	bits := p.Addr().BitLen()
	if p.Bits() > bits-2 {
		return prefix, server, fmt.Errorf("tunnel subnet %q is too small for a server and a user", cidr)
	}
	if size := uint64(1) << (bits - p.Bits()); size > maxPool {
		return prefix, server, fmt.Errorf("tunnel subnet %q is too large (at most %d addresses)", cidr, maxPool)
	}
	return p, p.Addr().Next(), nil
}

// poolAddresses lists the addresses a peer may take: every host of the subnet
// except the first, which is the server's.
func poolAddresses(prefix netip.Prefix) []netip.Addr {
	bits := prefix.Addr().BitLen()
	size := uint64(1) << (bits - prefix.Bits())
	out := make([]netip.Addr, 0, size-1)
	addr := prefix.Addr()
	for i := uint64(0); i < size; i++ {
		if i > 0 {
			out = append(out, addr)
		}
		addr = addr.Next()
	}
	return out
}

// assignAddresses maps every peer key of the user set to its inner address.
//
// WireGuard has no sessions: the device only knows which peer sent a packet,
// so the netstack sees the packet's source address, and a unique inner address
// per user is what names the user of a connection. The panel renders client
// configs without asking the node, so the assignment must be reproducible from
// the key set alone:
//
//   - keys are sorted, so the order of users does not matter;
//   - the preferred slot is a hash of the key reduced into the pool;
//   - a slot a smaller key already holds is skipped (linear probing).
func assignAddresses(keys [][32]byte, pool []netip.Addr) map[[32]byte]netip.Addr {
	sorted := make([][32]byte, len(keys))
	copy(sorted, keys)
	sort.Slice(sorted, func(i, j int) bool { return lessKey(sorted[i], sorted[j]) })

	out := make(map[[32]byte]netip.Addr, len(sorted))
	taken := make([]bool, len(pool))
	for _, key := range sorted {
		if len(pool) == 0 {
			break
		}
		hash := blake2b.Sum256(key[:])
		start := (int(hash[0])<<8 | int(hash[1])) % len(pool)
		for i := 0; i < len(pool); i++ {
			slot := (start + i) % len(pool)
			if taken[slot] {
				continue
			}
			taken[slot] = true
			out[key] = pool[slot]
			break
		}
	}
	return out
}

func lessKey(a, b [32]byte) bool {
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// hexKey is the UAPI form of a key.
func hexKey(key [32]byte) string { return hex.EncodeToString(key[:]) }

// b64decode accepts the base64 forms a WireGuard key comes in: standard or
// URL-safe, with or without padding.
func b64decode(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw, nil
		}
	}
	return nil, errors.New("not base64")
}

func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }

// decodeKey reads a 32-byte key written in hex or base64.
func decodeKey(s string) ([32]byte, error) {
	var out [32]byte
	if len(s) == 64 {
		if raw, err := hex.DecodeString(s); err == nil {
			copy(out[:], raw)
			return out, nil
		}
	}
	raw, err := b64decode(s)
	if err != nil {
		return out, fmt.Errorf("decode key: %w", err)
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("decode key: expected 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}
