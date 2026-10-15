#!/bin/sh
# Downloads the pinned Xray-core and mihomo release binaries into $1 and checks
# their SHA-256. Runs inside an alpine container (see run.sh). The pins are the
# ones of .github/workflows/interop.yml.
set -eu

XRAY_VERSION=v26.10.10
XRAY_SHA256=72a5fde819713a103c6fc26a87aa025c1518c918a34eba4bc38d64dc0728e5d9
MIHOMO_VERSION=v1.19.32
MIHOMO_SHA256=8451100836c9eda194331c2babfad490b2faf30cebc1a04b0e76fd8ac2d35d10

out=${1:?usage: fetch.sh OUTDIR}
mkdir -p "$out"
cd "$out"

if [ ! -x xray ] || [ "$(cat xray.version 2>/dev/null)" != "$XRAY_VERSION" ]; then
	base="https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION"
	wget -q -O Xray-linux-64.zip "$base/Xray-linux-64.zip"
	wget -q -O Xray-linux-64.zip.dgst "$base/Xray-linux-64.zip.dgst"
	dgst=$(sed -n 's/^SHA2-256= *\([0-9a-f]\{64\}\).*/\1/p' Xray-linux-64.zip.dgst)
	actual=$(sha256sum Xray-linux-64.zip | cut -d' ' -f1)
	echo "xray zip: pinned $XRAY_SHA256 dgst $dgst actual $actual"
	if [ "$actual" != "$XRAY_SHA256" ] || [ "$actual" != "$dgst" ]; then
		echo "Xray-linux-64.zip SHA-256 mismatch" >&2
		exit 1
	fi
	unzip -o -q Xray-linux-64.zip xray
	chmod +x xray
	rm -f Xray-linux-64.zip Xray-linux-64.zip.dgst
	echo "$XRAY_VERSION" > xray.version
fi

if [ ! -x mihomo ] || [ "$(cat mihomo.version 2>/dev/null)" != "$MIHOMO_VERSION" ]; then
	file="mihomo-linux-amd64-$MIHOMO_VERSION.gz"
	wget -q -O "$file" "https://github.com/MetaCubeX/mihomo/releases/download/$MIHOMO_VERSION/$file"
	actual=$(sha256sum "$file" | cut -d' ' -f1)
	echo "mihomo gz: pinned $MIHOMO_SHA256 actual $actual"
	if [ "$actual" != "$MIHOMO_SHA256" ]; then
		echo "$file SHA-256 mismatch" >&2
		exit 1
	fi
	gunzip -c "$file" > mihomo
	chmod +x mihomo
	rm -f "$file"
	echo "$MIHOMO_VERSION" > mihomo.version
fi

./xray version | head -1
./mihomo -v | head -1
