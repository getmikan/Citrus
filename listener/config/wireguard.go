package config

import (
	"encoding/json"
)

// WireGuardServer is the `listeners:` entry of a WireGuard / AmneziaWG server.
//
// The listener runs in userspace only: no TUN device, no NET_ADMIN, no
// wg-quick. The node gives it one UDP port and one private key; every user is
// a peer whose key pair is derived from the user's secret, so the panel never
// stores a client private key.
type WireGuardServer struct {
	Enable     bool              `yaml:"enable" json:"enable"`
	Listen     string            `yaml:"listen" json:"listen"`
	Users      map[string]string `yaml:"users" json:"users,omitempty"`
	PrivateKey string            `yaml:"private-key" json:"private-key,omitempty"`
	MTU        int               `yaml:"mtu" json:"mtu,omitempty"`
	// IPv4CIDR and IPv6CIDR are the tunnel subnets. The first host address of
	// each is the server; every user gets one /32 (or /128) of its own, which
	// is what makes an inbound packet's source address name its user.
	IPv4CIDR string `yaml:"ipv4-cidr" json:"ipv4-cidr,omitempty"`
	IPv6CIDR string `yaml:"ipv6-cidr" json:"ipv6-cidr,omitempty"`
	Workers  int    `yaml:"workers" json:"workers,omitempty"`
	// AmneziaWG obfuscation. Version 3 selects the v3 implementation, any
	// other value the legacy one; the parameters of 3.x are silently ignored
	// by the legacy implementation, so the choice must follow the version.
	AmneziaWG *AmneziaWGServer `yaml:"amnezia-wg-option" json:"amnezia-wg-option,omitempty"`
}

// AmneziaWGServer mirrors the client-side amnezia-wg-option of the outbound
// (adapter/outbound/wireguard.go), with the same key names.
type AmneziaWGServer struct {
	Version int `yaml:"version" json:"version,omitempty"`

	JC   int `yaml:"jc" json:"jc,omitempty"`
	JMin int `yaml:"jmin" json:"jmin,omitempty"`
	JMax int `yaml:"jmax" json:"jmax,omitempty"`
	S1   int `yaml:"s1" json:"s1,omitempty"`
	S2   int `yaml:"s2" json:"s2,omitempty"`
	S3   int `yaml:"s3" json:"s3,omitempty"`
	S4   int `yaml:"s4" json:"s4,omitempty"`

	H1 string `yaml:"h1" json:"h1,omitempty"`
	H2 string `yaml:"h2" json:"h2,omitempty"`
	H3 string `yaml:"h3" json:"h3,omitempty"`
	H4 string `yaml:"h4" json:"h4,omitempty"`

	I1 string `yaml:"i1" json:"i1,omitempty"`
	I2 string `yaml:"i2" json:"i2,omitempty"`
	I3 string `yaml:"i3" json:"i3,omitempty"`
	I4 string `yaml:"i4" json:"i4,omitempty"`
	I5 string `yaml:"i5" json:"i5,omitempty"`

	J1    string `yaml:"j1" json:"j1,omitempty"`
	J2    string `yaml:"j2" json:"j2,omitempty"`
	J3    string `yaml:"j3" json:"j3,omitempty"`
	Itime int64  `yaml:"itime" json:"itime,omitempty"`

	HeaderProtectionKey    string `yaml:"header-protection-key" json:"header-protection-key,omitempty"`
	ContentPaddingAddition string `yaml:"content-padding-addition" json:"content-padding-addition,omitempty"`
	RekeyAfterTime         string `yaml:"rekey-after-time" json:"rekey-after-time,omitempty"`
	RekeyTimeout           string `yaml:"rekey-timeout" json:"rekey-timeout,omitempty"`
	RejectAfterTime        string `yaml:"reject-after-time" json:"reject-after-time,omitempty"`
	KeepaliveTimeout       string `yaml:"keepalive-timeout" json:"keepalive-timeout,omitempty"`
	MaxHandshakeAttempts   string `yaml:"max-handshake-attempts" json:"max-handshake-attempts,omitempty"`
	RandomTrailers         bool   `yaml:"random-trailers" json:"random-trailers,omitempty"`
	DisableCookies         bool   `yaml:"disable-cookies" json:"disable-cookies,omitempty"`
}

func (t WireGuardServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
