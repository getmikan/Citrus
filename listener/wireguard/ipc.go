package wireguard

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	LC "github.com/metacubex/mihomo/listener/config"
)

// peer is one user of the listener as the device sees it.
type peer struct {
	user      string
	publicKey [32]byte
	address   netip.Addr
}

// ipcConfig renders the UAPI set string: the private key, the obfuscation
// parameters and every peer with its own inner address.
//
// The same call serves the first start and every user change. A set operation
// is atomic, so a reload never leaves the listener without peers.
func ipcConfig(private [32]byte, awg *LC.AmneziaWGServer, peers []peer) (string, error) {
	var b strings.Builder
	b.Grow(256 + len(peers)*160)
	b.WriteString("private_key=")
	b.WriteString(hexKey(private))
	b.WriteByte('\n')

	if awg != nil {
		if err := writeAmneziaWG(&b, awg); err != nil {
			return "", err
		}
	}

	// replace_peers makes the operation authoritative: a peer missing from this
	// string is removed, which is how a user is deleted without a restart.
	b.WriteString("replace_peers=true\n")
	for _, p := range peers {
		b.WriteString("public_key=")
		b.WriteString(hexKey(p.publicKey))
		b.WriteByte('\n')
		bits := "/32"
		if p.address.Is6() {
			bits = "/128"
		}
		b.WriteString("allowed_ip=")
		b.WriteString(p.address.String())
		b.WriteString(bits)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// ValidateAmneziaWG checks obfuscation parameters before anything is started:
// the failures of these parameters are silent on the wire (the handshake just
// never converges), so they must be caught here.
func ValidateAmneziaWG(awg *LC.AmneziaWGServer) error {
	if awg == nil {
		return nil
	}
	if awg.JC < 0 || awg.JMin < 0 || awg.JMax < 0 {
		return errors.New("amnezia-wg: jc, jmin and jmax cannot be negative")
	}
	if awg.JMin > awg.JMax {
		return errors.New("amnezia-wg: jmin must not exceed jmax")
	}
	for name, v := range map[string]int{"s1": awg.S1, "s2": awg.S2, "s3": awg.S3, "s4": awg.S4} {
		if v < 0 || v > 65535 {
			return fmt.Errorf("amnezia-wg: %s out of range", name)
		}
	}
	// A handshake initiation is 148 bytes and a response 92, so s1 and s2 that differ by
	// 56 make the two messages the same length on the wire: the obfuscation then separates
	// nothing, and a censor sees one size for both. No end reports it.
	if awg.S1 != 0 && awg.S2 != 0 && awg.S2 == awg.S1+56 {
		return errors.New("amnezia-wg: s2 must not be s1+56: the initiation and the response would be the same size")
	}
	if awg.Version == 3 {
		if awg.HeaderProtectionKey == "" {
			return errors.New("amnezia-wg: version 3 needs a header-protection-key")
		}
		// A header protection key needs room for the encrypted header: with a
		// smaller padding the handshake never converges, and no error says why.
		for name, v := range map[string]int{"s1": awg.S1, "s2": awg.S2, "s3": awg.S3, "s4": awg.S4} {
			if v < 12 {
				return fmt.Errorf("amnezia-wg: header-protection-key needs %s of at least 12, got %d", name, v)
			}
		}
		if _, err := decodeKey(awg.HeaderProtectionKey); err != nil {
			return fmt.Errorf("amnezia-wg: header-protection-key: %w", err)
		}
	}
	for name, v := range map[string]string{
		"h1": awg.H1, "h2": awg.H2, "h3": awg.H3, "h4": awg.H4,
	} {
		if v == "" {
			continue
		}
		if err := checkUintRange(v); err != nil {
			return fmt.Errorf("amnezia-wg: %s: %w", name, err)
		}
	}
	for name, v := range map[string]string{
		"content-padding-addition": awg.ContentPaddingAddition,
		"rekey-after-time":         awg.RekeyAfterTime,
		"rekey-timeout":            awg.RekeyTimeout,
		"reject-after-time":        awg.RejectAfterTime,
		"keepalive-timeout":        awg.KeepaliveTimeout,
		"max-handshake-attempts":   awg.MaxHandshakeAttempts,
	} {
		if v == "" {
			continue
		}
		if err := checkUintRange(v); err != nil {
			return fmt.Errorf("amnezia-wg: %s: %w", name, err)
		}
	}
	return nil
}

// writeAmneziaWG writes the obfuscation parameters. Only the parameters of the
// implementation the version selects are written: the 3.x ones mean nothing to
// the legacy device, and writing them would look like they work.
func writeAmneziaWG(b *strings.Builder, awg *LC.AmneziaWGServer) error {
	writeInt := func(key string, v int) {
		if v != 0 {
			b.WriteString(key)
			b.WriteByte('=')
			b.WriteString(strconv.Itoa(v))
			b.WriteByte('\n')
		}
	}
	writeStr := func(key, v string) {
		if v != "" {
			b.WriteString(key)
			b.WriteByte('=')
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}

	writeInt("jc", awg.JC)
	writeInt("jmin", awg.JMin)
	writeInt("jmax", awg.JMax)
	writeInt("s1", awg.S1)
	writeInt("s2", awg.S2)
	writeInt("s3", awg.S3)
	writeInt("s4", awg.S4)
	writeStr("h1", awg.H1)
	writeStr("h2", awg.H2)
	writeStr("h3", awg.H3)
	writeStr("h4", awg.H4)
	writeStr("i1", awg.I1)
	writeStr("i2", awg.I2)
	writeStr("i3", awg.I3)
	writeStr("i4", awg.I4)
	writeStr("i5", awg.I5)

	if awg.Version != 3 {
		// The 1.5-only parameters are unknown to the v3 device.
		writeStr("j1", awg.J1)
		writeStr("j2", awg.J2)
		writeStr("j3", awg.J3)
		if awg.Itime != 0 {
			b.WriteString("itime=")
			b.WriteString(strconv.FormatInt(awg.Itime, 10))
			b.WriteByte('\n')
		}
		return nil
	}

	key, err := decodeKey(awg.HeaderProtectionKey)
	if err != nil {
		return fmt.Errorf("amnezia-wg: header-protection-key: %w", err)
	}
	writeStr("header_protection_key", hexKey(key))
	writeStr("content_padding_addition", awg.ContentPaddingAddition)
	writeStr("rekey_after_time", awg.RekeyAfterTime)
	writeStr("rekey_timeout", awg.RekeyTimeout)
	writeStr("reject_after_time", awg.RejectAfterTime)
	writeStr("keepalive_timeout", awg.KeepaliveTimeout)
	writeStr("max_handshake_attempts", awg.MaxHandshakeAttempts)
	if awg.RandomTrailers {
		b.WriteString("random_trailers=1\n")
	}
	if awg.DisableCookies {
		b.WriteString("disable_cookies=1\n")
	}
	return nil
}

// checkUintRange validates a UAPI "a" or "a-b" numeric value.
func checkUintRange(s string) error {
	lo, hi, isRange := strings.Cut(s, "-")
	if _, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 32); err != nil {
		return fmt.Errorf("invalid number %q", s)
	}
	if isRange {
		if _, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 32); err != nil {
			return fmt.Errorf("invalid range %q", s)
		}
	}
	return nil
}

// sortedPeers orders peers by key so the UAPI string is stable between
// reloads, which keeps the device from touching unaffected peers.
func sortedPeers(peers []peer) []peer {
	out := make([]peer, len(peers))
	copy(out, peers)
	sort.Slice(out, func(i, j int) bool { return lessKey(out[i].publicKey, out[j].publicKey) })
	return out
}
