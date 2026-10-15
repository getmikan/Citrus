package core

import (
	"crypto/md5"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
)

type Cipher interface {
	StreamConnCipher
	PacketConnCipher
}

type StreamConnCipher interface {
	StreamConn(net.Conn) net.Conn
}

type PacketConnCipher interface {
	PacketConn(N.EnhancePacketConn) N.EnhancePacketConn
}

// ErrCipherNotSupported occurs when a cipher is not supported (likely because of security concerns).
var ErrCipherNotSupported = errors.New("cipher not supported")

// ErrStreamCipherRemoved occurs when a legacy (pre-AEAD) stream cipher is requested.
var ErrStreamCipherRemoved = fmt.Errorf("%w: shadowsocks stream ciphers are no longer supported, use an AEAD cipher (aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305) or 2022-blake3-*", C.ErrRemovedProtocol)

const (
	aeadAes128Gcm         = "AEAD_AES_128_GCM"
	aeadAes192Gcm         = "AEAD_AES_192_GCM"
	aeadAes256Gcm         = "AEAD_AES_256_GCM"
	aeadChacha20Poly1305  = "AEAD_CHACHA20_POLY1305"
	aeadXChacha20Poly1305 = "AEAD_XCHACHA20_POLY1305"
	aeadChacha8Poly1305   = "AEAD_CHACHA8_POLY1305"
	aeadXChacha8Poly1305  = "AEAD_XCHACHA8_POLY1305"
	aeadAes128Ccm         = "AEAD_AES_128_CCM"
	aeadAes192Ccm         = "AEAD_AES_192_CCM"
	aeadAes256Ccm         = "AEAD_AES_256_CCM"
)

// List of AEAD ciphers: key size in bytes and constructor
var aeadList = map[string]struct {
	KeySize int
	New     func([]byte) (shadowaead.Cipher, error)
}{
	aeadAes128Gcm:         {16, shadowaead.AESGCM},
	aeadAes192Gcm:         {24, shadowaead.AESGCM},
	aeadAes256Gcm:         {32, shadowaead.AESGCM},
	aeadChacha20Poly1305:  {32, shadowaead.Chacha20Poly1305},
	aeadXChacha20Poly1305: {32, shadowaead.XChacha20Poly1305},
	aeadChacha8Poly1305:   {32, shadowaead.Chacha8Poly1305},
	aeadXChacha8Poly1305:  {32, shadowaead.XChacha8Poly1305},
	aeadAes128Ccm:         {16, shadowaead.AESCCM},
	aeadAes192Ccm:         {24, shadowaead.AESCCM},
	aeadAes256Ccm:         {32, shadowaead.AESCCM},
}

// legacyStreamCiphers are the removed pre-AEAD stream ciphers, kept only to give a clear error.
var legacyStreamCiphers = map[string]struct{}{
	"TABLE":         {},
	"RC4":           {},
	"RC4-MD5":       {},
	"AES-128-CTR":   {},
	"AES-192-CTR":   {},
	"AES-256-CTR":   {},
	"AES-128-CFB":   {},
	"AES-192-CFB":   {},
	"AES-256-CFB":   {},
	"CHACHA20":      {},
	"CHACHA20-IETF": {},
	"XCHACHA20":     {},
}

// IsStreamCipher reports whether name is one of the removed legacy stream ciphers.
func IsStreamCipher(name string) bool {
	_, ok := legacyStreamCiphers[strings.ToUpper(name)]
	return ok
}

// ListCipher returns a list of available cipher names sorted alphabetically.
func ListCipher() []string {
	var l []string
	for k := range aeadList {
		l = append(l, k)
	}
	sort.Strings(l)
	return l
}

// PickCipher returns a Cipher of the given name. Derive key from password if given key is empty.
func PickCipher(name string, key []byte, password string) (Cipher, error) {
	name = strings.ToUpper(name)

	switch name {
	case "DUMMY":
		return &dummy{}, nil
	case "CHACHA20-IETF-POLY1305":
		name = aeadChacha20Poly1305
	case "XCHACHA20-IETF-POLY1305":
		name = aeadXChacha20Poly1305
	case "AES-128-GCM":
		name = aeadAes128Gcm
	case "AES-192-GCM":
		name = aeadAes192Gcm
	case "AES-256-GCM":
		name = aeadAes256Gcm
	case "CHACHA8-IETF-POLY1305":
		name = aeadChacha8Poly1305
	case "XCHACHA8-IETF-POLY1305":
		name = aeadXChacha8Poly1305
	case "AES-128-CCM":
		name = aeadAes128Ccm
	case "AES-192-CCM":
		name = aeadAes192Ccm
	case "AES-256-CCM":
		name = aeadAes256Ccm
	}

	if choice, ok := aeadList[name]; ok {
		if len(key) == 0 {
			key = Kdf(password, choice.KeySize)
		}
		if len(key) != choice.KeySize {
			return nil, shadowaead.KeySizeError(choice.KeySize)
		}
		aead, err := choice.New(key)
		return &AeadCipher{Cipher: aead, Key: key}, err
	}

	if IsStreamCipher(name) {
		return nil, ErrStreamCipherRemoved
	}

	return nil, ErrCipherNotSupported
}

type AeadCipher struct {
	shadowaead.Cipher

	Key []byte
}

func (aead *AeadCipher) StreamConn(c net.Conn) net.Conn { return shadowaead.NewConn(c, aead) }
func (aead *AeadCipher) PacketConn(c N.EnhancePacketConn) N.EnhancePacketConn {
	return shadowaead.NewPacketConn(c, aead)
}

// dummy cipher does not encrypt

type dummy struct{}

func (dummy) StreamConn(c net.Conn) net.Conn                       { return c }
func (dummy) PacketConn(c N.EnhancePacketConn) N.EnhancePacketConn { return c }

// key-derivation function from original Shadowsocks
func Kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}
