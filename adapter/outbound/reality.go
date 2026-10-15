package outbound

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	tlsC "github.com/metacubex/mihomo/component/tls"
)

type RealityOptions struct {
	PublicKey     string `proxy:"public-key"`
	ShortID       string `proxy:"short-id,omitempty"`
	ClientVersion string `proxy:"client-version,omitempty"`
	Mldsa65Verify string `proxy:"mldsa65-verify,omitempty"`

	// SupportX25519MLKEM768 is enabled by default, Xray v26.9.8+ servers require it.
	// Set it to false only for old REALITY servers.
	SupportX25519MLKEM768 *bool `proxy:"support-x25519mlkem768,omitempty"`
}

func (o RealityOptions) Parse() (*tlsC.RealityConfig, error) {
	if o.PublicKey != "" {
		config := new(tlsC.RealityConfig)
		config.DisableX25519MLKEM768 = o.SupportX25519MLKEM768 != nil && !*o.SupportX25519MLKEM768

		const x25519ScalarSize = 32
		publicKey, err := base64.RawURLEncoding.DecodeString(o.PublicKey)
		if err != nil || len(publicKey) != x25519ScalarSize {
			return nil, errors.New("invalid REALITY public key")
		}
		config.PublicKey, err = ecdh.X25519().NewPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("fail to create REALITY public key: %w", err)
		}

		n := hex.DecodedLen(len(o.ShortID))
		if n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short id")
		}
		n, err = hex.Decode(config.ShortID[:], []byte(o.ShortID))
		if err != nil || n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short ID")
		}

		clientVersion := o.ClientVersion
		if clientVersion == "" {
			clientVersion = tlsC.RealityDefaultClientVersion
		}
		config.ClientVersion, err = tlsC.ParseRealityClientVersion(clientVersion)
		if err != nil {
			return nil, err
		}

		if o.Mldsa65Verify != "" {
			config.Mldsa65Verify, err = tlsC.ParseRealityMldsa65Verify(o.Mldsa65Verify)
			if err != nil {
				return nil, err
			}
		}

		return config, nil
	}
	return nil, nil
}
