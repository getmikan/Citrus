// Package interop runs Citrus against a real Xray-core binary, both ways round,
// against an upstream mihomo release binary as the client (the core of the
// apps the panel's users run), and against a sing-box release binary (the core
// of SFA/SFI, Hiddify and NekoBox), on localhost only.
//
//	cd test/interop
//	XRAY_BIN=/path/to/xray go test -tags interop -v ./...
//	MIHOMO_BIN=/path/to/mihomo go test -tags interop -v -run TestMihomoClient ./...
//	SINGBOX_BIN=/path/to/sing-box go test -tags interop -v -run Singbox ./...
//	XRAY_BIN=/path/to/xray go test -tags interop -v -run TestXDriveInterop ./...
//
// XDRIVE needs an Xray binary containing transport/internet/xdrive. Its tests
// cover local and template storage, both client/server directions, native
// VLESS Encryption 0rtt/1rtt, parallel TCP streams and XUDP. They use local
// storage/API fixtures and never require cloud credentials.
//
// XRAY_BIN unset: the Xray tests are skipped; MIHOMO_BIN unset: the mihomo
// ones (mihomo_test.go); SINGBOX_BIN unset: the sing-box ones
// (singbox_test.go). INTEROP_TUIC_OVER_LIMIT set: also run the sing-box TUIC
// case past the server's stream limit, a known failure. CITRUS_BIN: a
// prebuilt Citrus binary (default: built from the repository root).
// INTEROP_LOG_DIR: where the process logs go (default: a temporary directory,
// removed afterwards).
//
// Traffic goes to a local HTTP echo server, and the REALITY target is a local
// TLS 1.3 server whose Certificate message is large enough for ML-DSA-65.
package interop
