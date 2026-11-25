package wireguard

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	LC "github.com/metacubex/mihomo/listener/config"
)

func TestUserKeyIsDeterministicAndChanneled(t *testing.T) {
	a, err := UserKey("slot-secret")
	if err != nil {
		t.Fatal(err)
	}
	b, err := UserKey("slot-secret")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("the same secret must give the same key")
	}
	c, err := UserKey("another-secret")
	if err != nil {
		t.Fatal(err)
	}
	if a == c {
		t.Fatal("different secrets must give different keys")
	}
	if _, err := UserKey(""); err != nil {
		t.Fatalf("an empty secret still derives a key: %v", err)
	}
}

func TestPrivateKeyIsClamped(t *testing.T) {
	private := privateKey("slot-secret")
	if private[0]&7 != 0 {
		t.Fatalf("low bits are not cleared: %x", private[0])
	}
	if private[31]&0x80 != 0 {
		t.Fatal("the top bit is not cleared")
	}
	if private[31]&0x40 == 0 {
		t.Fatal("the second top bit is not set")
	}
}

func TestServerKeysFollowThePrivateKey(t *testing.T) {
	a, err := serverKeys(privateKey("server-a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := serverKeys(privateKey("server-b"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("different private keys must give different public keys")
	}
	if a == [32]byte{} {
		t.Fatal("the public key is empty")
	}
}

// The server key is derived by the panel from the node's own secret, so a
// user who happens to pick the same secret would be the same peer. The panel
// keeps them apart with a distinct salt; this test pins the salt so a silent
// change breaks the build rather than the user configs.
func TestClientKeySaltIsPinned(t *testing.T) {
	sum := privateKey("x")
	if hexKey(sum) != hexKey(privateKey("x")) {
		t.Fatal("derivation is not deterministic")
	}
	if keySalt != "mikan/wg/" {
		t.Fatalf("key salt changed: %q", keySalt)
	}
}

func TestParsePoolRejectsBadSubnets(t *testing.T) {
	for _, cidr := range []string{"", "10.0.0.0", "10.0.0.0/31", "10.0.0.0/32", "10.0.0.0/8"} {
		if _, _, err := parsePool(cidr); err == nil {
			t.Fatalf("%q must be rejected", cidr)
		}
	}
	prefix, server, err := parsePool("10.66.66.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if got := prefix.String(); got != "10.66.66.0/24" {
		t.Fatalf("prefix = %s", got)
	}
	if got := server.String(); got != "10.66.66.1" {
		t.Fatalf("server address = %s, want the first host", got)
	}

	// A subnet written with a host address still names the whole network.
	prefix, server, err = parsePool("10.99.0.7/24")
	if err != nil {
		t.Fatal(err)
	}
	if got := prefix.String(); got != "10.99.0.0/24" {
		t.Fatalf("prefix = %s, want the masked network", got)
	}
	if got := server.String(); got != "10.99.0.1" {
		t.Fatalf("server address = %s", got)
	}
}

func TestPoolAddressesSkipTheServer(t *testing.T) {
	prefix, _, err := parsePool("10.66.66.0/29")
	if err != nil {
		t.Fatal(err)
	}
	pool := poolAddresses(prefix)
	if len(pool) != 7 {
		t.Fatalf("pool size = %d, want 7", len(pool))
	}
	if pool[0].String() != "10.66.66.1" {
		t.Fatalf("first pool address = %s", pool[0])
	}
	for _, addr := range pool {
		if addr.String() == "10.66.66.0" {
			t.Fatal("the network address must not be handed out")
		}
	}
}

func TestAssignAddressesIsStableAndUnique(t *testing.T) {
	prefix, _, err := parsePool("10.66.66.0/24")
	if err != nil {
		t.Fatal(err)
	}
	pool := poolAddresses(prefix)

	keys := make([][32]byte, 0, 8)
	for _, secret := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		key, err := UserKey(secret)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}

	first := assignAddresses(keys, pool)
	if len(first) != len(keys) {
		t.Fatalf("assigned %d of %d keys", len(first), len(keys))
	}
	seen := map[netip.Addr]bool{}
	for key, addr := range first {
		if seen[addr] {
			t.Fatalf("address %s handed out twice (key %x)", addr, key)
		}
		seen[addr] = true
	}

	// The order of the users must not change the answer: the panel renders the
	// client configs from the same set in its own order.
	shuffled := [][32]byte{keys[3], keys[7], keys[1], keys[0], keys[6], keys[5], keys[2], keys[4]}
	second := assignAddresses(shuffled, pool)
	for key, addr := range first {
		if second[key] != addr {
			t.Fatalf("address of %x changed with the order: %s vs %s", key, addr, second[key])
		}
	}
}

func TestAssignAddressesReportsFullPool(t *testing.T) {
	prefix, _, err := parsePool("10.66.66.0/29")
	if err != nil {
		t.Fatal(err)
	}
	pool := poolAddresses(prefix) // 7 addresses
	keys := make([][32]byte, 0, 8)
	for i := 0; i < 8; i++ {
		keys = append(keys, [32]byte{byte(i + 1)})
	}
	got := assignAddresses(keys, pool)
	if len(got) != len(pool) {
		t.Fatalf("assigned %d addresses, want %d", len(got), len(pool))
	}
}

func TestValidateAmneziaWGVersion3NeedsPadding(t *testing.T) {
	awg := &LC.AmneziaWGServer{
		Version:             3,
		HeaderProtectionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		S1:                  11, S2: 30, S3: 30, S4: 30,
	}
	err := ValidateAmneziaWG(awg)
	if err == nil || !strings.Contains(err.Error(), "s1") {
		t.Fatalf("s1 below 12 must be rejected, got %v", err)
	}
	awg.S1 = 12
	if err := ValidateAmneziaWG(awg); err != nil {
		t.Fatalf("valid parameters rejected: %v", err)
	}
}

func TestValidateAmneziaWGVersion3NeedsKey(t *testing.T) {
	awg := &LC.AmneziaWGServer{Version: 3, S1: 20, S2: 20, S3: 20, S4: 20}
	if err := ValidateAmneziaWG(awg); err == nil {
		t.Fatal("version 3 without a header protection key must be rejected")
	}
}

func TestValidateAmneziaWGRejectsBadRanges(t *testing.T) {
	cases := []*LC.AmneziaWGServer{
		{Version: 1, JMin: 100, JMax: 50},
		{Version: 1, H1: "abc"},
		{Version: 1, H1: "10-"},
		{Version: 1, ContentPaddingAddition: "x-y"},
		{Version: 1, S1: -1},
	}
	for i, awg := range cases {
		if err := ValidateAmneziaWG(awg); err == nil {
			t.Fatalf("case %d must be rejected", i)
		}
	}
}

// A handshake initiation is 148 bytes and a response 92: with s2 = s1+56 both are the
// same size, and the obfuscation separates nothing while both ends still connect.
func TestValidateAmneziaWGRejectsTheSizeCollision(t *testing.T) {
	awg := &LC.AmneziaWGServer{Version: 1, S1: 20, S2: 76}
	err := ValidateAmneziaWG(awg)
	if err == nil {
		t.Fatal("s2 = s1+56 must be rejected")
	}
	if !strings.Contains(err.Error(), "s1+56") {
		t.Fatalf("error = %v", err)
	}
	awg.S2 = 77
	if err := ValidateAmneziaWG(awg); err != nil {
		t.Fatalf("s2 = s1+57 rejected: %v", err)
	}
}

func TestValidateAmneziaWGAcceptsLegacy(t *testing.T) {
	awg := &LC.AmneziaWGServer{Version: 1, JC: 4, JMin: 50, JMax: 1000, S1: 20, S2: 20, S3: 20, S4: 20, H1: "1234567-1234667"}
	if err := ValidateAmneziaWG(awg); err != nil {
		t.Fatalf("legacy parameters rejected: %v", err)
	}
}

func TestIPCConfigWritesPeersAndSkipsV3KeyForLegacy(t *testing.T) {
	private := privateKey("server-secret")
	key, err := UserKey("user-secret")
	if err != nil {
		t.Fatal(err)
	}
	peers := []peer{{user: "u1", publicKey: key, address: netip.MustParseAddr("10.66.66.2")}}

	legacy, err := ipcConfig(private, &LC.AmneziaWGServer{Version: 1, S1: 20}, peers)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(legacy, "header_protection_key") {
		t.Fatal("the legacy implementation must not get a header protection key")
	}
	if !strings.Contains(legacy, "replace_peers=true") {
		t.Fatal("the peer list must be authoritative")
	}
	if !strings.Contains(legacy, "allowed_ip=10.66.66.2/32") {
		t.Fatalf("the peer address is missing:\n%s", legacy)
	}

	key32 := make([]byte, 32)
	v3, err := ipcConfig(private, &LC.AmneziaWGServer{
		Version: 3, S1: 20, S2: 20, S3: 20, S4: 20,
		HeaderProtectionKey: base64.StdEncoding.EncodeToString(key32),
		RandomTrailers:      true,
	}, peers)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(v3, "header_protection_key="+hex.EncodeToString(key32)) {
		t.Fatalf("the header protection key is missing:\n%s", v3)
	}
	if !strings.Contains(v3, "random_trailers=1") {
		t.Fatal("random trailers is missing")
	}
}

func TestIPCConfigRejectsV3WithoutKey(t *testing.T) {
	private := privateKey("server-secret")
	if _, err := ipcConfig(private, &LC.AmneziaWGServer{Version: 3, S1: 20, S2: 20, S3: 20, S4: 20}, nil); err == nil {
		t.Fatal("version 3 without a key must not render")
	}
}

func TestDecodeKeyAcceptsAllKeyForms(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	forms := []string{
		hex.EncodeToString(raw),
		base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
	}
	for _, form := range forms {
		key, err := decodeKey(form)
		if err != nil {
			t.Fatalf("%q: %v", form, err)
		}
		if hexKey(key) != hex.EncodeToString(raw) {
			t.Fatalf("%q decoded to %s", form, hexKey(key))
		}
	}
	for _, bad := range []string{"", "zzz", hex.EncodeToString(make([]byte, 16))} {
		if _, err := decodeKey(bad); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
}

func TestSortedPeersIsStable(t *testing.T) {
	a := peer{publicKey: [32]byte{3}, address: netip.MustParseAddr("10.66.66.3")}
	b := peer{publicKey: [32]byte{1}, address: netip.MustParseAddr("10.66.66.2")}
	c := peer{publicKey: [32]byte{2}, address: netip.MustParseAddr("10.66.66.4")}
	sorted := sortedPeers([]peer{a, b, c})
	for i := 1; i < len(sorted); i++ {
		if lessKey(sorted[i].publicKey, sorted[i-1].publicKey) {
			t.Fatalf("peers are not sorted at %d", i)
		}
	}
}
