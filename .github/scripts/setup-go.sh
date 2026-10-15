#!/usr/bin/env bash
# Installs a pinned Go toolchain on a linux/amd64 runner and checks it
# against .github/go-toolchains.txt before anything runs it.
#
# Usage: setup-go.sh <key>     key is a manifest entry: 1.26, loong64-abi1, ...
#
# The manifest line gives the exact Go version, the tarball URL and its
# SHA-256. A tarball that does not match, or holds another Go version, is
# rejected and the job fails. The MetaCubeX/go `build` release replaces its
# assets in place when it is rebuilt, so a mismatch right after such a
# rebuild is expected: check the new asset and update the version and hash
# (`gh release view build -R MetaCubeX/go --json assets` lists the digests).
# Never update the hash without knowing why it changed.
#
# On success the toolchain is in $RUNNER_TEMP/go-<key>, its bin directory is
# added to GITHUB_PATH and GOROOT is set in GITHUB_ENV.
set -euo pipefail

key="${1:?usage: setup-go.sh <key>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest="${here}/../go-toolchains.txt"

line="$(awk -v k="$key" '$1 == k { print; exit }' "$manifest")"
if [ -z "$line" ]; then
	echo "::error::no Go toolchain '${key}' in .github/go-toolchains.txt"
	exit 1
fi
read -r _ version url want <<<"$line"

dest="${RUNNER_TEMP:?}/go-${key}"
tarball="${RUNNER_TEMP}/go-${key}.tar.gz"

# Two rounds of curl's own retries, 30 seconds apart: the release host
# sometimes fails for a minute at a time.
fetch() {
	curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors -o "$tarball" "$url"
}
if ! fetch; then
	echo "Go download failed, retrying in 30 seconds"
	sleep 30
	fetch
fi

got="$(sha256sum "$tarball" | cut -d' ' -f1)"
echo "toolchain: ${url}"
echo "pinned:    ${want}"
echo "actual:    ${got}"
if [ "$got" != "$want" ]; then
	echo "::error::Go toolchain '${key}' SHA-256 mismatch (see .github/scripts/setup-go.sh)"
	exit 1
fi

# The tarballs hold go/ or ./go/; both extract to go/.
rm -rf "$dest" "${dest}.x"
mkdir -p "${dest}.x"
tar -xzf "$tarball" -C "${dest}.x"
rm -f "$tarball"
mv "${dest}.x/go" "$dest"
rm -rf "${dest}.x"

have="$(head -n1 "${dest}/VERSION")"
if [ "$have" != "$version" ]; then
	echo "::error::Go toolchain '${key}' is ${have}, the manifest says ${version}"
	exit 1
fi

echo "${dest}/bin" >>"$GITHUB_PATH"
echo "GOROOT=${dest}" >>"$GITHUB_ENV"
"${dest}/bin/go" version
