package reality

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/authevent"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"

	utls "github.com/metacubex/utls"
)

type Conn = utls.Conn
type LimitFallback = utls.RealityLimitFallback

type Config struct {
	Dest              string
	PrivateKey        string
	ShortID           []string
	ServerNames       []string
	MaxTimeDifference int // milliseconds, like Xray's maxTimeDiff
	Proxy             string

	// Mldsa65Seed is Xray's mldsa65Seed: the base64url (unpadded) encoded 32-byte ML-DSA-65 seed.
	// The server then signs its temporary certificate, which clients with the matching
	// mldsa65-verify (see utls.RealityMldsa65Verify) require.
	Mldsa65Seed string
	// RequireX25519MLKEM768 rejects (forwards to dest) client hellos without an X25519MLKEM768
	// key share placed before X25519, like Xray v26.9.8+ does.
	RequireX25519MLKEM768 bool
	// MinClientVer and MaxClientVer limit the Xray version ("x.y.z") reported by clients.
	MinClientVer string
	MaxClientVer string

	LimitFallbackUpload   LimitFallback
	LimitFallbackDownload LimitFallback
}

func (c Config) Build(tunnel C.Tunnel) (*Builder, error) {
	realityConfig := &utls.RealityConfig{}
	realityConfig.SessionTicketsDisabled = true
	realityConfig.Type = "tcp"
	realityConfig.Dest = c.Dest
	realityConfig.Time = ntp.Now
	realityConfig.ServerNames = make(map[string]bool)
	realityConfig.Log = log.Debugln
	for _, it := range c.ServerNames {
		realityConfig.ServerNames[it] = true
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(privateKey) != 32 {
		return nil, errors.New("invalid private key")
	}
	realityConfig.PrivateKey = privateKey

	// Xray's maxTimeDiff is in milliseconds (transport/internet/reality/config.go)
	realityConfig.MaxTimeDiff = time.Duration(c.MaxTimeDifference) * time.Millisecond

	if c.Mldsa65Seed != "" {
		if c.Mldsa65Seed == c.PrivateKey {
			return nil, errors.New("mldsa65-seed and private-key can not be the same value")
		}
		seed, err := base64.RawURLEncoding.DecodeString(c.Mldsa65Seed)
		if err != nil || len(seed) != utls.RealityMldsa65SeedSize {
			return nil, fmt.Errorf("invalid mldsa65-seed: %s", c.Mldsa65Seed)
		}
		if _, err = utls.RealityMldsa65Verify(seed); err != nil {
			return nil, fmt.Errorf("invalid mldsa65-seed: %w", err)
		}
		realityConfig.Mldsa65Seed = seed
	}
	realityConfig.RequireX25519MLKEM768 = c.RequireX25519MLKEM768
	if realityConfig.MinClientVer, err = parseClientVer(c.MinClientVer); err != nil {
		return nil, fmt.Errorf("invalid min-client-ver: %w", err)
	}
	if realityConfig.MaxClientVer, err = parseClientVer(c.MaxClientVer); err != nil {
		return nil, fmt.Errorf("invalid max-client-ver: %w", err)
	}

	realityConfig.ShortIds = make(map[[8]byte]bool)
	for i, shortIDString := range c.ShortID {
		var shortID [8]byte
		decodedLen := hex.DecodedLen(len(shortIDString))
		if decodedLen > 8 {
			return nil, fmt.Errorf("invalid short_id[%d]: %s", i, shortIDString)
		}
		decodedLen, err = hex.Decode(shortID[:], []byte(shortIDString))
		if err != nil {
			return nil, fmt.Errorf("decode short_id[%d] '%s': %w", i, shortIDString, err)
		}
		if decodedLen > 8 {
			return nil, fmt.Errorf("invalid short_id[%d]: %s", i, shortIDString)
		}
		realityConfig.ShortIds[shortID] = true
	}

	realityConfig.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return inner.HandleTcp(tunnel, address, c.Proxy)
	}

	realityConfig.LimitFallbackUpload = c.LimitFallbackUpload
	realityConfig.LimitFallbackDownload = c.LimitFallbackDownload

	return &Builder{realityConfig}, nil
}

// parseClientVer parses an Xray version like "26.10.10" into 3 bytes, nil for an empty one.
func parseClientVer(version string) ([]byte, error) {
	if version == "" {
		return nil, nil
	}
	clientVer, err := tlsC.ParseRealityClientVersion(version)
	if err != nil {
		return nil, err
	}
	return clientVer[:], nil
}

type Builder struct {
	realityConfig *utls.RealityConfig
}

func (b Builder) NewListener(l net.Listener) net.Listener {
	return N.NewHandleContextListener(context.Background(), l, func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		c, err := utls.RealityServer(ctx, conn, b.realityConfig)
		if err != nil {
			authevent.EmitAddr("reality", authevent.ReasonRejectedHandshake, conn.LocalAddr(), conn.RemoteAddr())
			return nil, err
		}
		// Due to low implementation quality, the reality server intercepted half-close and caused memory leaks.
		// We fixed it by calling Close() directly.
		return realityConnWrapper{c}, nil
	}, func(a any) {
		stack := debug.Stack()
		log.Errorln("reality server panic: %s\n%s", a, stack)
	})
}

type realityConnWrapper struct {
	*utls.Conn
}

func (c realityConnWrapper) Upstream() any {
	return c.Conn
}

func (c realityConnWrapper) CloseWrite() error {
	return c.Close()
}

func (c realityConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c realityConnWrapper) WriterReplaceable() bool {
	return true
}
