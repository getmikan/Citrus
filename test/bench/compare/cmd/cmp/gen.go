package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type obj = map[string]any

// material is the key material shared by the server configs and the client.
type material struct {
	CertPEM     string `json:"cert_pem"`
	KeyPEM      string `json:"key_pem"`
	CertSHA256  string `json:"cert_sha256"` // hex SHA-256 of the leaf DER (Xray pinnedPeerCertSha256)
	RealityPriv string `json:"reality_private_key"`
	RealityPub  string `json:"reality_public_key"`
	ShortID     string `json:"short_id"`
	UUID        string `json:"uuid"`
	TrojanPass  string `json:"trojan_password"`
	SSPSK       string `json:"ss_psk"` // 2022-blake3-aes-128-gcm key, base64
}

var servers = []string{"xray", "mihomo", "citrus"}

// serverProtos are the inbounds; the client-side variants map onto them (baseProto).
var serverProtos = []string{"reality", "xhttp", "trojan", "ss2022"}

func baseProto(p string) string {
	switch p {
	case "reality-x25519", "reality-tlsin":
		return "reality"
	}
	return p
}

func newMaterial() (*material, error) {
	m := &material{}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: benchSNI},
		DNSNames:     []string{benchSNI},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	m.CertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	m.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}))
	m.CertSHA256 = hex.EncodeToString(sum[:])

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	m.RealityPriv = base64.RawURLEncoding.EncodeToString(priv.Bytes())
	m.RealityPub = base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	m.ShortID = hex.EncodeToString(randBytes(8))
	u := randBytes(16)
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	m.UUID = fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
	m.TrojanPass = hex.EncodeToString(randBytes(16))
	m.SSPSK = base64.StdEncoding.EncodeToString(randBytes(16))
	return m, nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func cmdGen(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	out := fs.String("out", "", "output directory (mounted read-only at /cfg in the server containers)")
	redacted := fs.String("redacted", "", "also write the configs here with the keys replaced (for the record)")
	fs.Parse(args)
	if *out == "" {
		return fmt.Errorf("-out is required")
	}
	m, err := newMaterial()
	if err != nil {
		return err
	}
	if *redacted != "" {
		r := material{
			CertPEM: "<redacted: self-signed P-256 certificate for " + benchSNI + ">", KeyPEM: "<redacted>",
			CertSHA256: "<redacted>", RealityPriv: "<redacted>", RealityPub: "<redacted>",
			ShortID: "<redacted>", UUID: "<redacted>", TrojanPass: "<redacted>", SSPSK: "<redacted>",
		}
		for _, p := range serverProtos {
			if err := writeJSON(filepath.Join(*redacted, "server-xray-"+p+".json"), xrayServer(&r, p)); err != nil {
				return err
			}
			if err := writeJSON(filepath.Join(*redacted, "server-mihomo-citrus-"+p+".yaml"), clashServer(&r, p)); err != nil {
				return err
			}
		}
		for _, p := range protoOrder {
			if err := writeJSON(filepath.Join(*redacted, "client-xray-"+p+".json"), xrayClient(&r, p, serverIP, serverPort, 1080)); err != nil {
				return err
			}
		}
	}
	if err := writeJSON(filepath.Join(*out, "material.json"), m); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "cert.pem"), []byte(m.CertPEM), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "key.pem"), []byte(m.KeyPEM), 0o644); err != nil {
		return err
	}
	for _, p := range serverProtos {
		if err := writeJSON(filepath.Join(*out, "xray", p+".json"), xrayServer(m, p)); err != nil {
			return err
		}
		// mihomo and Citrus read the same config (JSON is valid YAML).
		for _, s := range []string{"mihomo", "citrus"} {
			if err := writeJSON(filepath.Join(*out, s, p+".yaml"), clashServer(m, p)); err != nil {
				return err
			}
		}
	}
	fmt.Println("configs written to", *out)
	return nil
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	return os.WriteFile(path, b.Bytes(), 0o644)
}

// --- servers ----------------------------------------------------------------------

func xrayServer(m *material, proto string) obj {
	in := obj{"listen": "0.0.0.0", "port": serverPort}
	tls := obj{
		"security": "tls",
		"tlsSettings": obj{"certificates": []obj{{
			"certificateFile": "/cfg/cert.pem", "keyFile": "/cfg/key.pem",
		}}},
	}
	switch proto {
	case "reality":
		in["protocol"] = "vless"
		in["settings"] = obj{"clients": []obj{{"id": m.UUID, "flow": "xtls-rprx-vision"}}, "decryption": "none"}
		in["streamSettings"] = obj{"network": "raw", "security": "reality", "realitySettings": obj{
			"target":      fmt.Sprintf("%s:%d", sinkIP, targetPort),
			"serverNames": []string{benchSNI},
			"privateKey":  m.RealityPriv,
			"shortIds":    []string{m.ShortID},
		}}
	case "xhttp":
		in["protocol"] = "vless"
		in["settings"] = obj{"clients": []obj{{"id": m.UUID}}, "decryption": "none"}
		ts := tls["tlsSettings"].(obj)
		ts["alpn"] = []string{"h2"}
		in["streamSettings"] = obj{
			"network": "xhttp", "xhttpSettings": obj{"path": "/xh", "mode": "stream-one"},
			"security": "tls", "tlsSettings": ts,
		}
	case "trojan":
		in["protocol"] = "trojan"
		in["settings"] = obj{"clients": []obj{{"password": m.TrojanPass}}}
		in["streamSettings"] = obj{"network": "raw", "security": "tls", "tlsSettings": tls["tlsSettings"]}
	case "ss2022":
		in["protocol"] = "shadowsocks"
		in["settings"] = obj{"method": "2022-blake3-aes-128-gcm", "password": m.SSPSK, "network": "tcp"}
	}
	return obj{
		"log":      obj{"loglevel": "warning", "access": "none"},
		"inbounds": []obj{in},
		// Since v26 Xray refuses private destinations for proxy inbounds unless a
		// final rule allows them; the sink is on a private address.
		"outbounds": []obj{{"protocol": "freedom", "settings": obj{"finalRules": []obj{{"action": "allow"}}}}},
	}
}

// clashServer is the mihomo / Citrus config: one listener, everything DIRECT.
func clashServer(m *material, proto string) obj {
	l := obj{"name": "in", "listen": "0.0.0.0", "port": serverPort}
	switch proto {
	case "reality":
		l["type"] = "vless"
		l["users"] = []obj{{"username": "u", "uuid": m.UUID, "flow": "xtls-rprx-vision"}}
		l["reality-config"] = obj{
			"dest":         fmt.Sprintf("%s:%d", sinkIP, targetPort),
			"private-key":  m.RealityPriv,
			"short-id":     []string{m.ShortID},
			"server-names": []string{benchSNI},
		}
	case "xhttp":
		l["type"] = "vless"
		l["users"] = []obj{{"username": "u", "uuid": m.UUID}}
		l["certificate"] = m.CertPEM
		l["private-key"] = m.KeyPEM
		l["xhttp-config"] = obj{"path": "/xh", "mode": "stream-one"}
	case "trojan":
		l["type"] = "trojan"
		l["users"] = []obj{{"username": "u", "password": m.TrojanPass}}
		l["certificate"] = m.CertPEM
		l["private-key"] = m.KeyPEM
	case "ss2022":
		l["type"] = "shadowsocks"
		l["cipher"] = "2022-blake3-aes-128-gcm"
		l["password"] = m.SSPSK
		l["udp"] = false
	}
	return obj{
		"log-level":         "warning",
		"ipv6":              false,
		"find-process-mode": "off",
		"listeners":         []obj{l},
		"rules":             []string{"MATCH,DIRECT"},
	}
}

// --- client -----------------------------------------------------------------------

// Client fingerprints. REALITY's authentication is X25519 either way; these
// choose the TLS key exchange the client offers. The probe records what the
// server actually picked (keyshare in the results).
var (
	fpDefault = "chrome" // uTLS Chrome: X25519MLKEM768 + X25519 key shares
	fpX25519  = "ios"    // uTLS iOS 14: X25519 key share only
)

// xrayClient is the Xray client config: a SOCKS inbound on socksPort, one
// outbound to addr:port.
func xrayClient(m *material, proto, addr string, port, socksPort int) obj {
	var out obj
	tls := obj{"serverName": benchSNI, "pinnedPeerCertSha256": m.CertSHA256}
	switch baseProto(proto) {
	case "reality":
		fp := fpDefault
		if proto == "reality-x25519" {
			fp = fpX25519
		}
		out = obj{
			"protocol": "vless",
			"settings": obj{"vnext": []obj{{"address": addr, "port": port,
				"users": []obj{{"id": m.UUID, "encryption": "none", "flow": "xtls-rprx-vision"}}}}},
			"streamSettings": obj{"network": "raw", "security": "reality", "realitySettings": obj{
				"fingerprint": fp, "serverName": benchSNI, "password": m.RealityPub, "shortId": m.ShortID,
			}},
		}
	case "xhttp":
		tls["alpn"] = []string{"h2"}
		out = obj{
			"protocol": "vless",
			"settings": obj{"vnext": []obj{{"address": addr, "port": port,
				"users": []obj{{"id": m.UUID, "encryption": "none"}}}}},
			"streamSettings": obj{
				"network": "xhttp", "xhttpSettings": obj{"path": "/xh", "mode": "stream-one"},
				"security": "tls", "tlsSettings": tls,
			},
		}
	case "trojan":
		out = obj{
			"protocol":       "trojan",
			"settings":       obj{"servers": []obj{{"address": addr, "port": port, "password": m.TrojanPass}}},
			"streamSettings": obj{"network": "raw", "security": "tls", "tlsSettings": tls},
		}
	case "ss2022":
		out = obj{
			"protocol": "shadowsocks",
			"settings": obj{"servers": []obj{{"address": addr, "port": port,
				"method": "2022-blake3-aes-128-gcm", "password": m.SSPSK}}},
		}
	}
	return obj{
		"log": obj{"loglevel": "warning", "access": "none"},
		"inbounds": []obj{{"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": obj{"udp": false}}},
		"outbounds": []obj{out},
	}
}
