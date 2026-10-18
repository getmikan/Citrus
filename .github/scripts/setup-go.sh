#!/usr/bin/env bash
# Installs a pinned Go toolchain on a GitHub runner (Linux, macOS or Windows,
# amd64 or arm64) and checks it against .github/go-toolchains.txt before
# anything runs it. On Windows it runs in Git Bash (`shell: bash`).
#
# Usage: setup-go.sh <key>     key is a manifest entry: 1.26, loong64-abi1, ...
#
# The runner's platform (RUNNER_OS/RUNNER_ARCH, or uname outside Actions)
# picks the manifest line for the key; SETUP_GO_PLATFORM=<os>-<arch>
# overrides it. The line gives the exact Go version, the archive URL and its
# SHA-256. An archive that does not match, or holds another Go version, is
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

platform() {
	local os arch
	case "${RUNNER_OS:-$(uname -s)}" in
	Linux) os=linux ;;
	macOS | Darwin) os=darwin ;;
	Windows | MINGW* | MSYS* | CYGWIN*) os=windows ;;
	*) os=unknown ;;
	esac
	case "${RUNNER_ARCH:-$(uname -m)}" in
	X64 | x86_64 | amd64) arch=amd64 ;;
	ARM64 | arm64 | aarch64) arch=arm64 ;;
	*) arch=unknown ;;
	esac
	echo "${os}-${arch}"
}
plat="${SETUP_GO_PLATFORM:-$(platform)}"

line="$(awk -v k="$key" -v p="$plat" '$1 == k && $2 == p { print; exit }' "$manifest")"
if [ -z "$line" ]; then
	echo "::error::no Go toolchain '${key}' for ${plat} in .github/go-toolchains.txt"
	exit 1
fi
read -r _ _ version url want <<<"$line"

tmp="${RUNNER_TEMP:?}"
windows=false
if [ "${plat%%-*}" = windows ]; then
	windows=true
	# Mixed paths (C:/...) work for both the MSYS tools and native curl,
	# also under MSYS_NO_PATHCONV.
	tmp="$(cygpath -m "$tmp")"
fi
dest="${tmp}/go-${key}"
case "$url" in
*.zip) archive="${tmp}/go-${key}.zip" ;;
*) archive="${tmp}/go-${key}.tar.gz" ;;
esac

# Two rounds of curl's own retries, 30 seconds apart: the release host
# sometimes fails for a minute at a time.
fetch() {
	curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors -o "$archive" "$url"
}
if ! fetch; then
	echo "Go download failed, retrying in 30 seconds"
	sleep 30
	fetch
fi

if command -v sha256sum >/dev/null; then
	got="$(sha256sum <"$archive" | cut -d' ' -f1)"
else
	got="$(shasum -a 256 <"$archive" | cut -d' ' -f1)"
fi
echo "toolchain: ${url} (${plat})"
echo "pinned:    ${want}"
echo "actual:    ${got}"
if [ "$got" != "$want" ]; then
	echo "::error::Go toolchain '${key}' for ${plat}: SHA-256 mismatch (see .github/scripts/setup-go.sh)"
	exit 1
fi

# The archives hold go/ or ./go/; both extract to go/.
rm -rf "$dest" "${dest}.x"
mkdir -p "${dest}.x"
case "$archive" in
*.zip)
	if command -v unzip >/dev/null; then
		unzip -q "$archive" -d "${dest}.x"
	else
		# Windows' own bsdtar reads zip; Git Bash's GNU tar does not.
		"$(cygpath -u "${SYSTEMROOT:-C:/Windows}")/System32/tar.exe" -xf "$archive" -C "${dest}.x"
	fi
	;;
*) tar -xzf "$archive" -C "${dest}.x" ;;
esac
rm -f "$archive"
mv "${dest}.x/go" "$dest"
rm -rf "${dest}.x"

have="$(head -n1 "${dest}/VERSION" | tr -d '\r')"
if [ "$have" != "$version" ]; then
	echo "::error::Go toolchain '${key}' for ${plat} is ${have}, the manifest says ${version}"
	exit 1
fi

# The runner reads these files itself, so Windows gets Windows paths.
goroot="$dest"
gobin="${dest}/bin"
if $windows; then
	goroot="$(cygpath -w "$dest")"
	gobin="$(cygpath -w "${dest}/bin")"
fi
echo "$gobin" >>"$GITHUB_PATH"
echo "GOROOT=${goroot}" >>"$GITHUB_ENV"
GOTOOLCHAIN=local "${dest}/bin/go" version
