package trusttunnel

import "testing"

// Request streams are opened before Proxy-Authorization is checked, so the
// HTTP/3 server must not advertise an effectively unlimited stream count.
func TestServerQUICConfigStreamLimit(t *testing.T) {
	cfg := serverQUICConfig(false)
	if cfg.MaxIncomingStreams != serverMaxIncomingStreams {
		t.Fatalf("MaxIncomingStreams = %d, want %d", cfg.MaxIncomingStreams, serverMaxIncomingStreams)
	}
	if cfg.MaxIncomingStreams < 256 || cfg.MaxIncomingStreams > 4096 {
		t.Fatalf("MaxIncomingStreams = %d, want a bounded value", cfg.MaxIncomingStreams)
	}
	// 0 keeps the quic-go default (100), enough for the HTTP/3 control and
	// QPACK streams
	if cfg.MaxIncomingUniStreams < 0 || cfg.MaxIncomingUniStreams > 100 {
		t.Fatalf("MaxIncomingUniStreams = %d", cfg.MaxIncomingUniStreams)
	}
}
