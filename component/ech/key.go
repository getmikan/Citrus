package ech

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/component/ech/echparser"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/fswatch"
	"github.com/metacubex/tls"
	"golang.org/x/crypto/cryptobyte"
)

const (
	AEAD_AES_128_GCM      = 0x0001
	AEAD_AES_256_GCM      = 0x0002
	AEAD_ChaCha20Poly1305 = 0x0003
)

const extensionEncryptedClientHello = 0xfe0d
const DHKEM_X25519_HKDF_SHA256 = 0x0020
const KDF_HKDF_SHA256 = 0x0001

// sortedSupportedAEADs is just a sorted version of hpke.SupportedAEADS.
// We need this so that when we insert them into ECHConfigs the ordering
// is stable.
var sortedSupportedAEADs = []uint16{AEAD_AES_128_GCM, AEAD_AES_256_GCM, AEAD_ChaCha20Poly1305}

func marshalECHConfig(id uint8, pubKey []byte, publicName string, maxNameLen uint8) []byte {
	builder := cryptobyte.NewBuilder(nil)

	builder.AddUint16(extensionEncryptedClientHello)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddUint8(id)

		builder.AddUint16(DHKEM_X25519_HKDF_SHA256) // The only DHKEM we support
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddBytes(pubKey)
		})
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			for _, aeadID := range sortedSupportedAEADs {
				builder.AddUint16(KDF_HKDF_SHA256) // The only KDF we support
				builder.AddUint16(aeadID)
			}
		})
		builder.AddUint8(maxNameLen)
		builder.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddBytes([]byte(publicName))
		})
		builder.AddUint16(0) // extensions
	})

	return builder.BytesOrPanic()
}

func GenECHConfig(publicName string) (configBase64 string, keyPem string, err error) {
	echKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return
	}

	echConfig := marshalECHConfig(0, echKey.PublicKey().Bytes(), publicName, 0)

	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddBytes(echConfig)
	})
	echConfigList := builder.BytesOrPanic()

	builder2 := cryptobyte.NewBuilder(nil)
	builder2.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddBytes(echKey.Bytes())
	})
	builder2.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddBytes(echConfig)
	})
	echConfigKeys := builder2.BytesOrPanic()

	configBase64 = base64.StdEncoding.EncodeToString(echConfigList)
	keyPem = string(pem.EncodeToMemory(&pem.Block{Type: "ECH KEYS", Bytes: echConfigKeys}))
	return
}

func UnmarshalECHKeys(raw []byte) ([]tls.EncryptedClientHelloKey, error) {
	var keys []tls.EncryptedClientHelloKey
	rawString := cryptobyte.String(raw)
	for !rawString.Empty() {
		var key tls.EncryptedClientHelloKey
		if !rawString.ReadUint16LengthPrefixed((*cryptobyte.String)(&key.PrivateKey)) {
			return nil, errors.New("error parsing private key")
		}
		if !rawString.ReadUint16LengthPrefixed((*cryptobyte.String)(&key.Config)) {
			return nil, errors.New("error parsing config")
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("empty ECH keys")
	}
	return keys, nil
}

func LoadECHKey(key string, tlsConfig *tls.Config) error {
	if key == "" {
		return nil
	}
	echKeys, painTextErr := loadECHKey([]byte(key))
	if painTextErr == nil {
		tlsConfig.GetEncryptedClientHelloKeys = func(info *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			return echKeys, nil
		}
		return nil
	}
	key = C.Path.Resolve(key)
	var loadErr error
	if !C.Path.IsSafePath(key) {
		loadErr = C.Path.ErrNotSafePath(key)
	} else {
		var echKey []byte
		echKey, loadErr = os.ReadFile(key)
		if loadErr == nil {
			echKeys, loadErr = loadECHKey(echKey)
		}
	}
	if loadErr != nil {
		return fmt.Errorf("parse ECH keys failed, maybe format error:%s, or path error: %s", painTextErr.Error(), loadErr.Error())
	}
	gcFlag := new(os.File) // tiny (on the order of 16 bytes or less) and pointer-free objects may never run the finalizer, so we choose new an os.File
	updateMutex := sync.RWMutex{}
	if watcher, err := fswatch.NewWatcher(fswatch.Options{Path: []string{key}, Callback: func(path string) {
		updateMutex.Lock()
		defer updateMutex.Unlock()
		if echKey, err := os.ReadFile(key); err == nil {
			if newEchKeys, err := loadECHKey(echKey); err == nil {
				echKeys = newEchKeys
			}
		}
	}}); err == nil {
		if err = watcher.Start(); err == nil {
			runtime.SetFinalizer(gcFlag, func(f *os.File) {
				_ = watcher.Close()
			})
		}
	}
	tlsConfig.GetEncryptedClientHelloKeys = func(info *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
		defer runtime.KeepAlive(gcFlag)
		updateMutex.RLock()
		defer updateMutex.RUnlock()
		return echKeys, nil
	}
	return nil
}

// loadECHKey parses ECH server keys in one of the formats:
//   - PEM with one "ECH KEYS" block (citrus generate ech-keypair, xray tls ech --pem);
//     other blocks, such as the "ECH CONFIGS" one xray prints next to it, are ignored
//   - Xray echServerKeys: the same binary as plain base64 (xray tls ech), which may
//     hold several keys one after another
func loadECHKey(echKey []byte) ([]tls.EncryptedClientHelloKey, error) {
	var raw []byte
	if bytes.Contains(echKey, []byte("-----BEGIN")) {
		rest := echKey
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "ECH KEYS" {
				if raw != nil {
					return nil, errors.New("invalid ECH keys pem: more than one ECH KEYS block")
				}
				raw = block.Bytes
			}
		}
		if raw == nil || len(bytes.TrimSpace(rest)) > 0 {
			return nil, errors.New("invalid ECH keys pem")
		}
	} else {
		text := strings.Join(strings.Fields(string(echKey)), "") // a long base64 string may be wrapped
		if text == "" {
			return nil, errors.New("empty ECH keys")
		}
		var err error
		if raw, err = base64.StdEncoding.DecodeString(text); err != nil {
			if raw, err = base64.RawStdEncoding.DecodeString(text); err != nil {
				return nil, errors.New("invalid ECH keys: neither pem nor base64")
			}
		}
	}
	echKeys, err := UnmarshalECHKeys(raw)
	if err != nil {
		return nil, fmt.Errorf("parse ECH keys: %w", err)
	}
	for i, key := range echKeys {
		if len(key.PrivateKey) == 0 {
			return nil, fmt.Errorf("parse ECH keys: key %d: empty private key", i)
		}
		if _, _, err = echparser.ParseECHConfig(key.Config); err != nil {
			return nil, fmt.Errorf("parse ECH keys: key %d: %w", i, err)
		}
	}
	return echKeys, nil
}
