// Package interop runs Citrus against a real Xray-core binary, both ways round,
// and against an upstream mihomo release binary as the client (the core of the
// apps the panel's users run), on localhost only.
//
//	cd test/interop
//	XRAY_BIN=/path/to/xray go test -tags interop -v ./...
//	MIHOMO_BIN=/path/to/mihomo go test -tags interop -v -run TestMihomoClient ./...
//
// XRAY_BIN unset: the Xray tests are skipped; MIHOMO_BIN unset: the mihomo
// ones (mihomo_test.go). CITRUS_BIN: a prebuilt Citrus binary
// (default: built from the repository root). INTEROP_LOG_DIR: where the process
// logs go (default: a temporary directory, removed afterwards).
//
// Traffic goes to a local HTTP echo server, and the REALITY target is a local
// TLS 1.3 server whose Certificate message is large enough for ML-DSA-65.
package interop
