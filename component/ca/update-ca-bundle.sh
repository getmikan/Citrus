#!/bin/sh
# Refreshes ca-certificates.crt, the root bundle embedded into the core, from curl's extract of the
# Mozilla root store (https://curl.se/docs/caextract.html). The download is checked against the
# SHA-256 that curl publishes next to it; the header of the file records the Mozilla data date.
# Run it from anywhere, then review and commit the diff: make ca-bundle
set -eu

URL="https://curl.se/ca/cacert.pem"
dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/cacert.pem" "$URL"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/cacert.pem.sha256" "$URL.sha256"

want=$(cut -d ' ' -f 1 "$tmp/cacert.pem.sha256")
if command -v sha256sum >/dev/null 2>&1; then
	got=$(sha256sum "$tmp/cacert.pem" | cut -d ' ' -f 1)
else
	got=$(shasum -a 256 "$tmp/cacert.pem" | cut -d ' ' -f 1)
fi
if [ "$want" != "$got" ]; then
	echo "cacert.pem: SHA-256 $got does not match the published $want" >&2
	exit 1
fi
if ! grep -q 'BEGIN CERTIFICATE' "$tmp/cacert.pem"; then
	echo "cacert.pem: no certificates" >&2
	exit 1
fi

mv "$tmp/cacert.pem" "$dir/ca-certificates.crt"
echo "ca-certificates.crt: $(grep -c 'BEGIN CERTIFICATE' "$dir/ca-certificates.crt") roots," \
	"$(grep -m 1 'Certificate data from Mozilla' "$dir/ca-certificates.crt" | sed 's/^## *//')," \
	"SHA-256 $got"
