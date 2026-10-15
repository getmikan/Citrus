package tls

import (
	"context"
	"net"
	"reflect"
	"strings"
	"unsafe"

	"github.com/metacubex/mihomo/common/once"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/tls"
	utls "github.com/metacubex/utls"
	"github.com/mroth/weightedrand/v2"
	"golang.org/x/exp/slices"
)

type Conn = utls.Conn
type UConn = utls.UConn
type UClientHelloID = utls.ClientHelloID

const VersionTLS12 = utls.VersionTLS12
const VersionTLS13 = utls.VersionTLS13

func Client(c net.Conn, config *utls.Config) *Conn {
	return utls.Client(c, config)
}

func UClient(c net.Conn, config *utls.Config, fingerprint UClientHelloID) *UConn {
	return utls.UClient(c, config, fingerprint)
}

func Server(c net.Conn, config *utls.Config) *Conn {
	return utls.Server(c, config)
}

func NewListener(inner net.Listener, config *Config) net.Listener {
	return utls.NewListener(inner, config)
}

func GetFingerprint(clientFingerprint string) (UClientHelloID, bool) {
	clientFingerprint = strings.ToLower(clientFingerprint) // like Xray
	switch clientFingerprint {
	case "", "none", "unsafe", "hellogolang": // "unsafe" and "hellogolang" are Xray's names for no uTLS
		return UClientHelloID{}, false
	}

	if clientFingerprint == "random" {
		fingerprint := randomFingerprint()
		log.Debugln("use initial random HelloID:%s", fingerprint.Client)
		return fingerprint, true
	}

	if fingerprint, ok := fingerprints[clientFingerprint]; ok {
		log.Debugln("use specified fingerprint:%s", fingerprint.Client)
		return fingerprint, true
	} else {
		log.Warnln("wrong clientFingerprint:%s", clientFingerprint)
		return UClientHelloID{}, false
	}
}

var randomFingerprint = once.OnceValue(func() UClientHelloID {
	chooser, _ := weightedrand.NewChooser(
		weightedrand.NewChoice("chrome", 6),
		weightedrand.NewChoice("safari", 3),
		weightedrand.NewChoice("ios", 2),
		weightedrand.NewChoice("firefox", 1),
	)
	initClient := chooser.Pick()
	log.Debugln("initial random HelloID:%s", initClient)
	fingerprint, ok := fingerprints[initClient]
	if !ok {
		log.Warnln("error in initial random HelloID:%s", initClient)
	}
	return fingerprint
})

// chrome (Chrome 133), hellochrome_131, firefox (Firefox 148) and safari (Safari 26.3, both from
// the getmikan/utls fork) carry an X25519MLKEM768 key share of their own; chrome_pq* carry the
// obsolete X25519Kyber768Draft00; ios, android, edge, 360, qq and the older versions are classical
// ones. REALITY injects an X25519MLKEM768 key share into those, see UClientWithX25519MLKEM768.
var fingerprints = map[string]UClientHelloID{
	"chrome":  utls.HelloChrome_Auto,
	"firefox": utls.HelloFirefox_Auto,
	"safari":  utls.HelloSafari_Auto,
	"ios":     utls.HelloIOS_Auto,
	"android": utls.HelloAndroid_11_OkHttp,
	"edge":    utls.HelloEdge_Auto,
	"360":     utls.Hello360_Auto,
	"qq":      utls.HelloQQ_Auto,
	"random":  {},

	// classical fingerprints without X25519MLKEM768
	"chrome120":  utls.HelloChrome_120,
	"firefox120": utls.HelloFirefox_120,
	"safari16":   utls.HelloSafari_16_0,

	// deprecated fingerprints should not be used
	"chrome_psk":                 utls.HelloChrome_100_PSK,
	"chrome_psk_shuffle":         utls.HelloChrome_106_Shuffle,
	"chrome_padding_psk_shuffle": utls.HelloChrome_114_Padding_PSK_Shuf,
	"chrome_pq":                  utls.HelloChrome_115_PQ,
	"chrome_pq_psk":              utls.HelloChrome_115_PQ_PSK,
	"randomized":                 utls.HelloRandomized,
	"randomizedalpn":             utls.HelloRandomizedALPN,
	"randomizednoalpn":           utls.HelloRandomizedNoALPN,

	// names used by Xray-core (the `fp` of share links), see Xray's transport/internet/tls/tls.go.
	// The ones utls has no parrot for are mapped to the nearest available fingerprint.
	"hellofirefox_120":                 utls.HelloFirefox_120,
	"hellofirefox_148":                 utls.HelloFirefox_148,
	"hellochrome_120":                  utls.HelloChrome_120,
	"hellochrome_131":                  utls.HelloChrome_131,
	"hellochrome_133":                  utls.HelloChrome_133,
	"helloios_13":                      utls.HelloIOS_13,
	"helloios_14":                      utls.HelloIOS_14,
	"helloedge_106":                    utls.HelloEdge_Auto, // HelloEdge_106 seems to be incompatible with utls
	"hellosafari_26_3":                 utls.HelloSafari_26_3,
	"hello360_11_0":                    utls.Hello360_Auto, // Hello360_11_0 seems to be incompatible with utls
	"helloqq_11_1":                     utls.HelloQQ_11_1,
	"hellorandomized":                  utls.HelloRandomized,
	"hellorandomizedalpn":              utls.HelloRandomizedALPN,
	"hellorandomizednoalpn":            utls.HelloRandomizedNoALPN,
	"hellofirefox_auto":                utls.HelloFirefox_Auto,
	"hellofirefox_55":                  utls.HelloFirefox_55,
	"hellofirefox_56":                  utls.HelloFirefox_56,
	"hellofirefox_63":                  utls.HelloFirefox_63,
	"hellofirefox_65":                  utls.HelloFirefox_65,
	"hellofirefox_99":                  utls.HelloFirefox_99,
	"hellofirefox_102":                 utls.HelloFirefox_102,
	"hellofirefox_105":                 utls.HelloFirefox_105,
	"hellochrome_auto":                 utls.HelloChrome_Auto,
	"hellochrome_58":                   utls.HelloChrome_58,
	"hellochrome_62":                   utls.HelloChrome_62,
	"hellochrome_70":                   utls.HelloChrome_70,
	"hellochrome_72":                   utls.HelloChrome_72,
	"hellochrome_83":                   utls.HelloChrome_83,
	"hellochrome_87":                   utls.HelloChrome_87,
	"hellochrome_96":                   utls.HelloChrome_96,
	"hellochrome_100":                  utls.HelloChrome_100,
	"hellochrome_102":                  utls.HelloChrome_102,
	"hellochrome_106_shuffle":          utls.HelloChrome_106_Shuffle,
	"helloios_auto":                    utls.HelloIOS_Auto,
	"helloios_11_1":                    utls.HelloIOS_11_1,
	"helloios_12_1":                    utls.HelloIOS_12_1,
	"helloandroid_11_okhttp":           utls.HelloAndroid_11_OkHttp,
	"helloedge_85":                     utls.HelloEdge_85,
	"helloedge_auto":                   utls.HelloEdge_Auto,
	"hellosafari_16_0":                 utls.HelloSafari_16_0,
	"hellosafari_auto":                 utls.HelloSafari_Auto,
	"hello360_auto":                    utls.Hello360_Auto,
	"hello360_7_5":                     utls.Hello360_7_5,
	"helloqq_auto":                     utls.HelloQQ_Auto,
	"hellochrome_100_psk":              utls.HelloChrome_100_PSK,
	"hellochrome_112_psk_shuf":         utls.HelloChrome_112_PSK_Shuf,
	"hellochrome_114_padding_psk_shuf": utls.HelloChrome_114_Padding_PSK_Shuf,
	"hellochrome_115_pq":               utls.HelloChrome_115_PQ,
	"hellochrome_115_pq_psk":           utls.HelloChrome_115_PQ_PSK,
	"hellochrome_120_pq":               utls.HelloChrome_120_PQ,
}

func init() {
	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	for _, name := range []string{"randomized", "randomizedalpn", "randomizednoalpn", "hellorandomized", "hellorandomizedalpn", "hellorandomizednoalpn"} {
		randomized := fingerprints[name]
		randomized.Seed, _ = utls.NewPRNGSeed()
		randomized.Weights = &weights
		fingerprints[name] = randomized
	}
}

type Certificate = utls.Certificate

func UCertificate(it tls.Certificate) utls.Certificate {
	return utls.Certificate{
		Certificate: it.Certificate,
		PrivateKey:  it.PrivateKey,
		SupportedSignatureAlgorithms: utils.Map(it.SupportedSignatureAlgorithms, func(it tls.SignatureScheme) utls.SignatureScheme {
			return utls.SignatureScheme(it)
		}),
		OCSPStaple:                  it.OCSPStaple,
		SignedCertificateTimestamps: it.SignedCertificateTimestamps,
		Leaf:                        it.Leaf,
	}
}

type EncryptedClientHelloKey = utls.EncryptedClientHelloKey

func UEncryptedClientHelloKey(it tls.EncryptedClientHelloKey) utls.EncryptedClientHelloKey {
	return utls.EncryptedClientHelloKey{
		Config:      it.Config,
		PrivateKey:  it.PrivateKey,
		SendAsRetry: it.SendAsRetry,
	}
}

type ConnectionState = utls.ConnectionState

type Config = utls.Config

var tlsCertificateRequestInfoCtxOffset = utils.MustOK(reflect.TypeOf((*tls.CertificateRequestInfo)(nil)).Elem().FieldByName("ctx")).Offset
var tlsClientHelloInfoCtxOffset = utils.MustOK(reflect.TypeOf((*tls.ClientHelloInfo)(nil)).Elem().FieldByName("ctx")).Offset
var tlsConnectionStateEkmOffset = utils.MustOK(reflect.TypeOf((*tls.ConnectionState)(nil)).Elem().FieldByName("ekm")).Offset
var utlsConnectionStateEkmOffset = utils.MustOK(reflect.TypeOf((*utls.ConnectionState)(nil)).Elem().FieldByName("ekm")).Offset

func tlsConnectionState(state utls.ConnectionState) (tlsState tls.ConnectionState) {
	tlsState = tls.ConnectionState{
		Version:           state.Version,
		HandshakeComplete: state.HandshakeComplete,
		DidResume:         state.DidResume,
		CipherSuite:       state.CipherSuite,
		//CurveID:                     state.CurveID,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
		ECHAccepted:                 state.ECHAccepted,
		//HelloRetryRequest:           state.HelloRetryRequest,
	}
	// The layout of map, chan, and func types is equivalent to *T.
	// state.ekm is a func(label string, context []byte, length int) ([]byte, error)
	*(*unsafe.Pointer)(unsafe.Add(unsafe.Pointer(&tlsState), tlsConnectionStateEkmOffset)) =
		*(*unsafe.Pointer)(unsafe.Add(unsafe.Pointer(&state), utlsConnectionStateEkmOffset))
	return
}

func UConfig(config *tls.Config) *utls.Config {
	cfg := &utls.Config{
		Rand:                  config.Rand,
		Time:                  config.Time,
		Certificates:          utils.Map(config.Certificates, UCertificate),
		VerifyPeerCertificate: config.VerifyPeerCertificate,
		RootCAs:               config.RootCAs,
		NextProtos:            config.NextProtos,
		ServerName:            config.ServerName,
		ClientAuth:            utls.ClientAuthType(config.ClientAuth),
		ClientCAs:             config.ClientCAs,
		InsecureSkipVerify:    config.InsecureSkipVerify,
		CipherSuites:          config.CipherSuites,
		MinVersion:            config.MinVersion,
		MaxVersion:            config.MaxVersion,
		CurvePreferences: utils.Map(config.CurvePreferences, func(it tls.CurveID) utls.CurveID {
			return utls.CurveID(it)
		}),
		SessionTicketsDisabled: config.SessionTicketsDisabled,
		Renegotiation:          utls.RenegotiationSupport(config.Renegotiation),
		KeyLogWriter:           config.KeyLogWriter,
	}
	if config.GetClientCertificate != nil {
		cfg.GetClientCertificate = func(info *utls.CertificateRequestInfo) (*utls.Certificate, error) {
			tlsInfo := &tls.CertificateRequestInfo{
				AcceptableCAs: info.AcceptableCAs,
				SignatureSchemes: utils.Map(info.SignatureSchemes, func(it utls.SignatureScheme) tls.SignatureScheme {
					return tls.SignatureScheme(it)
				}),
				Version: info.Version,
			}
			*(*context.Context)(unsafe.Add(unsafe.Pointer(tlsInfo), tlsCertificateRequestInfoCtxOffset)) = info.Context() // for tlsInfo.ctx
			cert, err := config.GetClientCertificate(tlsInfo)
			if err != nil {
				return nil, err
			}
			uCert := UCertificate(*cert)
			return &uCert, err
		}
	}
	if config.GetCertificate != nil {
		cfg.GetCertificate = func(info *utls.ClientHelloInfo) (*utls.Certificate, error) {
			tlsInfo := &tls.ClientHelloInfo{
				CipherSuites: info.CipherSuites,
				ServerName:   info.ServerName,
				SupportedCurves: utils.Map(info.SupportedCurves, func(it utls.CurveID) tls.CurveID {
					return tls.CurveID(it)
				}),
				SupportedPoints: info.SupportedPoints,
				SignatureSchemes: utils.Map(info.SignatureSchemes, func(it utls.SignatureScheme) tls.SignatureScheme {
					return tls.SignatureScheme(it)
				}),
				SupportedProtos:   info.SupportedProtos,
				SupportedVersions: info.SupportedVersions,
				Extensions:        info.Extensions,
				Conn:              info.Conn,
				//HelloRetryRequest: info.HelloRetryRequest,
			}
			*(*context.Context)(unsafe.Add(unsafe.Pointer(tlsInfo), tlsClientHelloInfoCtxOffset)) = info.Context() // for tlsInfo.ctx
			cert, err := config.GetCertificate(tlsInfo)
			if err != nil {
				return nil, err
			}
			uCert := UCertificate(*cert)
			return &uCert, err
		}
	}
	if config.VerifyConnection != nil {
		cfg.VerifyConnection = func(state utls.ConnectionState) error {
			return config.VerifyConnection(tlsConnectionState(state))
		}
	}
	config.EncryptedClientHelloConfigList = cfg.EncryptedClientHelloConfigList
	if config.EncryptedClientHelloRejectionVerify != nil {
		cfg.EncryptedClientHelloRejectionVerify = func(state utls.ConnectionState) error {
			return config.EncryptedClientHelloRejectionVerify(tlsConnectionState(state))
		}
	}
	//cfg.GetEncryptedClientHelloKeys =
	cfg.EncryptedClientHelloKeys = utils.Map(config.EncryptedClientHelloKeys, UEncryptedClientHelloKey)
	return cfg
}

// BuildWebsocketHandshakeState it will only send http/1.1 in its ALPN.
// Copy from https://github.com/XTLS/Xray-core/blob/main/transport/internet/tls/tls.go
func BuildWebsocketHandshakeState(c *UConn) error {
	// Build the handshake state. This will apply every variable of the TLS of the
	// fingerprint in the UConn
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	// Iterate over extensions and check for utls.ALPNExtension
	hasALPNExtension := false
	for _, extension := range c.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			hasALPNExtension = true
			alpn.AlpnProtocols = []string{"http/1.1"}
			break
		}
	}
	if !hasALPNExtension { // Append extension if doesn't exists
		c.Extensions = append(c.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
	}
	// Rebuild the client hello
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	return nil
}

func BuildRemovedX25519MLKEM768HandshakeState(c *UConn) error {
	// Build the handshake state. This will apply every variable of the TLS of the
	// fingerprint in the UConn
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	// Iterate over extensions and check
	for _, extension := range c.Extensions {
		if ce, ok := extension.(*utls.SupportedCurvesExtension); ok {
			ce.Curves = slices.DeleteFunc(ce.Curves, func(curveID utls.CurveID) bool {
				return curveID == utls.X25519MLKEM768
			})
		}
		if ks, ok := extension.(*utls.KeyShareExtension); ok {
			ks.KeyShares = slices.DeleteFunc(ks.KeyShares, func(share utls.KeyShare) bool {
				return share.Group == utls.X25519MLKEM768
			})
		}
	}
	// Rebuild the client hello
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	return nil
}

// UClientWithX25519MLKEM768 returns a UConn with a built handshake state whose client hello
// offers an X25519MLKEM768 key share placed before the X25519 one. The fingerprints carrying such
// a key share themselves (chrome, firefox, safari) are used as they are, one is injected into
// the others (ios, android, edge, 360, qq, randomized, older versions).
func UClientWithX25519MLKEM768(c net.Conn, config *utls.Config, fingerprint UClientHelloID) (*UConn, error) {
	spec, err := utls.UTLSIdToSpec(fingerprint)
	if err != nil {
		return nil, err
	}
	if !NeedX25519MLKEM768(&spec) {
		uConn := utls.UClient(c, config, fingerprint)
		if err = uConn.BuildHandshakeState(); err != nil {
			return nil, err
		}
		return uConn, nil
	}
	AddX25519MLKEM768(&spec)
	uConn := utls.UClient(c, config, utls.HelloCustom)
	// ApplyPreset generates the key of every key share without data,
	// so the hybrid key of the injected X25519MLKEM768 share is a real one
	if err = uConn.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	if err = uConn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	return uConn, nil
}

// NeedX25519MLKEM768 reports whether the spec has a key_share extension but lacks a single
// X25519MLKEM768 key share placed before X25519 (in both supported_groups and key_share),
// or still offers the obsolete X25519Kyber768Draft00, so AddX25519MLKEM768 has to fix it.
func NeedX25519MLKEM768(spec *utls.ClientHelloSpec) bool {
	var curves []utls.CurveID
	var keyShares []utls.KeyShare
	hasKeyShare := false
	for _, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.SupportedCurvesExtension:
			curves = ext.Curves
		case *utls.KeyShareExtension:
			hasKeyShare = true
			keyShares = ext.KeyShares
		}
	}
	if !hasKeyShare {
		return false
	}
	pqFirst := func(groups []utls.CurveID) bool {
		pq, x25519 := -1, -1
		for i, group := range groups {
			switch group {
			case utls.X25519Kyber768Draft00:
				return false
			case utls.X25519MLKEM768:
				if pq >= 0 {
					return false
				}
				pq = i
			case utls.X25519:
				if x25519 < 0 {
					x25519 = i
				}
			}
		}
		return pq >= 0 && (x25519 < 0 || pq < x25519)
	}
	groups := make([]utls.CurveID, 0, len(keyShares))
	for _, share := range keyShares {
		groups = append(groups, share.Group)
	}
	return !pqFirst(curves) || !pqFirst(groups)
}

// AddX25519MLKEM768 makes the spec offer X25519MLKEM768 ahead of X25519 in both the
// supported_groups and the key_share extensions, replacing the obsolete X25519Kyber768Draft00.
// Xray REALITY servers since v26.9.8 drop any client hello without such a key share.
// A spec without a key_share extension (TLS 1.2 only) is left as it is.
func AddX25519MLKEM768(spec *utls.ClientHelloSpec) {
	if !slices.ContainsFunc(spec.Extensions, func(extension utls.TLSExtension) bool {
		_, ok := extension.(*utls.KeyShareExtension)
		return ok
	}) {
		return
	}
	for _, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.SupportedCurvesExtension:
			curves := slices.DeleteFunc(slices.Clone(ext.Curves), func(curveID utls.CurveID) bool {
				return curveID == utls.X25519MLKEM768 || curveID == utls.X25519Kyber768Draft00
			})
			i := pqInsertIndex(curves, func(curveID utls.CurveID) utls.CurveID { return curveID })
			ext.Curves = slices.Insert(curves, i, utls.X25519MLKEM768)
		case *utls.KeyShareExtension:
			keyShares := slices.DeleteFunc(slices.Clone(ext.KeyShares), func(share utls.KeyShare) bool {
				return share.Group == utls.X25519MLKEM768 || share.Group == utls.X25519Kyber768Draft00
			})
			i := pqInsertIndex(keyShares, func(share utls.KeyShare) utls.CurveID { return share.Group })
			ext.KeyShares = slices.Insert(keyShares, i, utls.KeyShare{Group: utls.X25519MLKEM768})
		}
	}
}

// pqInsertIndex returns the position of X25519, or the first position after the leading GREASE values.
func pqInsertIndex[T any](s []T, group func(T) utls.CurveID) int {
	if i := slices.IndexFunc(s, func(v T) bool { return group(v) == utls.X25519 }); i >= 0 {
		return i
	}
	i := 0
	for i < len(s) && isGREASE(uint16(group(s[i]))) {
		i++
	}
	return i
}

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v&0xff == v>>8
}

func GetTLSConnectionState(conn net.Conn) (tlsState tls.ConnectionState) {
	switch tlsConn := conn.(type) {
	case interface{ ConnectionState() tls.ConnectionState }:
		state := tlsConn.ConnectionState()
		return state
	case interface{ ConnectionState() utls.ConnectionState }:
		state := tlsConn.ConnectionState()
		return tlsConnectionState(state)
	}
	return
}
