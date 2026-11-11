package inbound

import "github.com/metacubex/mihomo/listener/fallback"

// Fallback is one of the fallbacks of a VLESS or Trojan inbound on its plain
// TCP transport (Xray-core "fallbacks"), see fallback.Target.
type Fallback struct {
	Name string `inbound:"name,omitempty"`
	ALPN string `inbound:"alpn,omitempty"`
	Path string `inbound:"path,omitempty"`
	Dest string `inbound:"dest"`
	Xver int    `inbound:"xver,omitempty"`
}

func buildFallbacks(options []Fallback) []fallback.Target {
	if len(options) == 0 {
		return nil
	}
	targets := make([]fallback.Target, len(options))
	for i, o := range options {
		targets[i] = fallback.Target{Name: o.Name, ALPN: o.ALPN, Path: o.Path, Dest: o.Dest, Xver: o.Xver}
	}
	return targets
}
