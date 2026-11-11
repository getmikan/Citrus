package tls

import (
	"net"
	"slices"
	"testing"

	utls "github.com/metacubex/utls"
)

func TestChromeFingerprintIsChrome155(t *testing.T) {
	for name, want := range map[string]UClientHelloID{
		"chrome":           utls.HelloChrome_155,
		"Chrome":           utls.HelloChrome_155,
		"chrome155":        utls.HelloChrome_155,
		"hellochrome_155":  utls.HelloChrome_155,
		"hellochrome_auto": utls.HelloChrome_155,
		"chrome133":        utls.HelloChrome_133,
		"hellochrome_133":  utls.HelloChrome_133,
	} {
		got, ok := GetFingerprint(name)
		if !ok || got != want {
			t.Errorf("%s: got %v (%v), want %v", name, got.Str(), ok, want.Str())
		}
	}
}

// chromeHello builds the ClientHello of the given fingerprint and returns the extension types
// and the signature schemes it offers.
func chromeHello(t *testing.T, name string) ([]uint16, []utls.SignatureScheme) {
	t.Helper()
	fingerprint, ok := GetFingerprint(name)
	if !ok {
		t.Fatalf("%s: unknown fingerprint", name)
	}
	uConn := UClient(&net.TCPConn{}, &utls.Config{ServerName: "example.com"}, fingerprint)
	if err := uConn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	raw := uConn.HandshakeState.Hello.Raw
	// handshake header (4), version (2), random (32)
	p := raw[4+2+32:]
	p = p[1+int(p[0]):]                   // session ID
	p = p[2+(int(p[0])<<8|int(p[1])):]    // cipher suites
	p = p[1+int(p[0]):]                   // compression methods
	p = p[2 : 2+(int(p[0])<<8|int(p[1]))] // extensions
	var extensions []uint16
	var schemes []utls.SignatureScheme
	for len(p) > 0 {
		id, length := uint16(p[0])<<8|uint16(p[1]), int(p[2])<<8|int(p[3])
		body := p[4 : 4+length]
		p = p[4+length:]
		extensions = append(extensions, id)
		if id == 13 { // signature_algorithms
			list := body[2:]
			for i := 0; i+1 < len(list); i += 2 {
				schemes = append(schemes, utls.SignatureScheme(uint16(list[i])<<8|uint16(list[i+1])))
			}
		}
	}
	return extensions, schemes
}

func TestChrome155ClientHello(t *testing.T) {
	const trustAnchors = 0xca34
	mldsa := []utls.SignatureScheme{0x0904, 0x0905, 0x0906}

	extensions, schemes := chromeHello(t, "chrome")
	if !slices.Contains(extensions, trustAnchors) {
		t.Errorf("chrome: no trust_anchors extension in %x", extensions)
	}
	if len(schemes) < 4 || !isGREASE(uint16(schemes[0])) || !slices.Equal(schemes[1:4], mldsa) {
		t.Errorf("chrome: signature_algorithms %x does not start with GREASE and ML-DSA-44/65/87", schemes)
	}

	extensions, schemes = chromeHello(t, "chrome133")
	if slices.Contains(extensions, trustAnchors) {
		t.Error("chrome133: unexpected trust_anchors extension")
	}
	for _, scheme := range schemes {
		if slices.Contains(mldsa, scheme) || isGREASE(uint16(scheme)) {
			t.Errorf("chrome133: unexpected signature scheme %x", scheme)
		}
	}
}
