package encryption

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// invalidValue reports a malformed encryption/decryption setting. The value
// holds keys (X25519 private keys and ML-KEM seeds for decryption), so the
// error names the dot-separated component that is wrong, never the value.
func invalidValue(kind string, component int, reason string) error {
	return fmt.Errorf("invalid vless %s value: component %d: %s", kind, component+1, reason)
}

// NewClient new client from encryption string
// maybe return a nil *ClientInstance without any error, that means don't need to encrypt
func NewClient(encryption string) (*ClientInstance, error) {
	switch encryption {
	case "", "none": // We will not reject empty string like xray-core does, because we need to ensure compatibility
		return nil, nil
	}
	if s := strings.Split(encryption, "."); len(s) >= 4 && s[0] == "mlkem768x25519plus" {
		var xorMode uint32
		switch s[1] {
		case "native":
		case "xorpub":
			xorMode = 1
		case "random":
			xorMode = 2
		default:
			return nil, invalidValue("encryption", 1, "mode must be native, xorpub or random")
		}
		var seconds uint32
		switch s[2] {
		case "1rtt":
		case "0rtt":
			seconds = 1
		default:
			return nil, invalidValue("encryption", 2, "must be 1rtt or 0rtt")
		}
		var nfsPKeysBytes [][]byte
		var paddings []string
		for idx, r := range s[3:] {
			if len(r) < 20 {
				paddings = append(paddings, r)
				continue
			}
			b, err := base64.RawURLEncoding.DecodeString(r)
			if err != nil {
				return nil, invalidValue("encryption", 3+idx, "key is not base64url")
			}
			if len(b) != X25519PasswordSize && len(b) != MLKEM768ClientLength {
				return nil, invalidValue("encryption", 3+idx, fmt.Sprintf("key is %d bytes, want %d (X25519) or %d (ML-KEM-768)", len(b), X25519PasswordSize, MLKEM768ClientLength))
			}
			nfsPKeysBytes = append(nfsPKeysBytes, b)
		}
		padding := strings.Join(paddings, ".")
		client := &ClientInstance{}
		if err := client.Init(nfsPKeysBytes, xorMode, seconds, padding); err != nil {
			return nil, fmt.Errorf("failed to use encryption: %w", err)
		}
		return client, nil
	}
	return nil, errors.New("invalid vless encryption value: want none or mlkem768x25519plus.<mode>.<rtt>.<keys>")
}

// NewServer new server from decryption string
// maybe return a nil *ServerInstance without any error, that means don't need to decrypt
func NewServer(decryption string) (*ServerInstance, error) {
	switch decryption {
	case "", "none": // We will not reject empty string like xray-core does, because we need to ensure compatibility
		return nil, nil
	}
	if s := strings.Split(decryption, "."); len(s) >= 4 && s[0] == "mlkem768x25519plus" {
		var xorMode uint32
		switch s[1] {
		case "native":
		case "xorpub":
			xorMode = 1
		case "random":
			xorMode = 2
		default:
			return nil, invalidValue("decryption", 1, "mode must be native, xorpub or random")
		}
		t := strings.SplitN(strings.TrimSuffix(s[2], "s"), "-", 2)
		i, err := strconv.Atoi(t[0])
		if err != nil {
			return nil, invalidValue("decryption", 2, "ticket lifetime must be <seconds>s or <from>-<to>s")
		}
		secondsFrom := int64(i)
		secondsTo := int64(0)
		if len(t) == 2 {
			i, err = strconv.Atoi(t[1])
			if err != nil {
				return nil, invalidValue("decryption", 2, "ticket lifetime must be <seconds>s or <from>-<to>s")
			}
			secondsTo = int64(i)
		}
		var nfsSKeysBytes [][]byte
		var paddings []string
		for idx, r := range s[3:] {
			if len(r) < 20 {
				paddings = append(paddings, r)
				continue
			}
			b, err := base64.RawURLEncoding.DecodeString(r)
			if err != nil {
				return nil, invalidValue("decryption", 3+idx, "key is not base64url")
			}
			if len(b) != X25519PrivateKeySize && len(b) != MLKEM768SeedLength {
				return nil, invalidValue("decryption", 3+idx, fmt.Sprintf("key is %d bytes, want %d (X25519) or %d (ML-KEM-768 seed)", len(b), X25519PrivateKeySize, MLKEM768SeedLength))
			}
			nfsSKeysBytes = append(nfsSKeysBytes, b)
		}
		padding := strings.Join(paddings, ".")
		server := &ServerInstance{}
		if err := server.Init(nfsSKeysBytes, xorMode, secondsFrom, secondsTo, padding); err != nil {
			return nil, fmt.Errorf("failed to use decryption: %w", err)
		}
		return server, nil
	}
	return nil, errors.New("invalid vless decryption value: want none or mlkem768x25519plus.<mode>.<ticket>.<keys>")
}
