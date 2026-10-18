#!/bin/sh
# Builds Citrus from the repository (mounted at /src) with the flags of the
# linux-amd64 release build (.github/workflows/build.yml: GOAMD64=v3,
# CGO_ENABLED=0, -tags with_gvisor, -trimpath, -ldflags "-extldflags --static
# ... -w -s -buildid="), and the cmp tool. Runs inside golang:<pinned> (run.sh),
# or with BUILD=host on the host's Go with SRC set to the repository (CI).
set -eu
out=${1:?usage: build.sh OUTDIR}
src=${SRC:-/src}
mkdir -p "$out"

cd "$src"
VERSION=${CITRUS_VERSION:-unknown}
BUILDTIME=$(date)
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v3 GOTOOLCHAIN=local
go build -o "$out/citrus" -tags "with_gvisor" -trimpath \
	-ldflags "-extldflags --static -X 'github.com/metacubex/mihomo/constant.Version=${VERSION}' -X 'github.com/metacubex/mihomo/constant.BuildTime=${BUILDTIME}' -w -s -buildid=" .
echo "$VERSION" > "$out/citrus.version"
"$out/citrus" -v | head -1

cd "$src/test/bench/compare"
go build -trimpath -o "$out/cmp" ./cmd/cmp
