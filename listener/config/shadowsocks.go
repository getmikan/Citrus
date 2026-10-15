package config

import (
	"github.com/metacubex/mihomo/listener/sing"

	"encoding/json"
)

type ShadowsocksServer struct {
	Enable     bool
	Listen     string
	Password   string
	Cipher     string
	Users      []ShadowsocksUser `yaml:"users" json:"users,omitempty"`
	Udp        bool
	MuxOption  sing.MuxOption `yaml:"mux-option" json:"mux-option,omitempty"`
	ShadowTLS  ShadowTLS      `yaml:"shadow-tls" json:"shadow-tls,omitempty"`
	ResTLS     ResTLS         `yaml:"res-tls" json:"res-tls,omitempty"`
	JLSConfig  JLSConfig      `yaml:"jls-config" json:"jls-config,omitempty"`
	KcpTun     KcpTun         `yaml:"kcp-tun" json:"kcp-tun,omitempty"`
	SimpleObfs SimpleObfs     `yaml:"simple-obfs" json:"simple-obfs,omitempty"`
}

// ShadowsocksUser is one user of a multi-user Shadowsocks 2022 server (EIH):
// Password is the user's base64 uPSK, the server's Password is the iPSK.
type ShadowsocksUser struct {
	Name     string `yaml:"name" json:"name"`
	Password string `yaml:"password" json:"password"`
}

type SimpleObfs struct {
	Enable bool
	Mode   string
}

func (t ShadowsocksServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
