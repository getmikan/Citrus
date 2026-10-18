#!/bin/sh
# Downloads the pinned Xray-core, sing-box and mihomo release binaries into $1
# and checks their SHA-256 (the pins are the release assets' digests on
# GitHub; Xray's is also checked against the release's .dgst file). Runs
# inside an alpine container (see run.sh).
set -eu

XRAY_VERSION=v26.10.17
XRAY_SHA256=ecdd54eccd24c4c21a8f00968e7dbf7f5996da92383d2321170b560dc4a95158
SINGBOX_VERSION=v1.14.3
SINGBOX_SHA256=41fc81fd041134d4d7d850a928d7d2cde17a7d6563953f406b22d32a68bfab1f
MIHOMO_VERSION=v1.19.32
MIHOMO_SHA256=8451100836c9eda194331c2babfad490b2faf30cebc1a04b0e76fd8ac2d35d10

out=${1:?usage: fetch.sh OUTDIR}
mkdir -p "$out"
cd "$out"

check() { # file pinned
	actual=$(sha256sum "$1" | cut -d' ' -f1)
	echo "$1: pinned $2 actual $actual"
	if [ "$actual" != "$2" ]; then
		echo "$1: SHA-256 mismatch" >&2
		exit 1
	fi
}

if [ ! -x xray ] || [ "$(cat xray.version 2>/dev/null)" != "$XRAY_VERSION" ]; then
	base="https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION"
	wget -q -O Xray-linux-64.zip "$base/Xray-linux-64.zip"
	wget -q -O Xray-linux-64.zip.dgst "$base/Xray-linux-64.zip.dgst"
	check Xray-linux-64.zip "$XRAY_SHA256"
	dgst=$(sed -n 's/^SHA2-256= *\([0-9a-f]\{64\}\).*/\1/p' Xray-linux-64.zip.dgst)
	if [ "$dgst" != "$XRAY_SHA256" ]; then
		echo "Xray-linux-64.zip: .dgst says $dgst" >&2
		exit 1
	fi
	unzip -o -q Xray-linux-64.zip xray
	chmod +x xray
	rm -f Xray-linux-64.zip Xray-linux-64.zip.dgst
	echo "$XRAY_VERSION" > xray.version
fi

if [ ! -x sing-box ] || [ "$(cat sing-box.version 2>/dev/null)" != "$SINGBOX_VERSION" ]; then
	v=${SINGBOX_VERSION#v}
	file="sing-box-$v-linux-amd64-musl.tar.gz" # musl: the runtime image is alpine
	wget -q -O "$file" "https://github.com/SagerNet/sing-box/releases/download/$SINGBOX_VERSION/$file"
	check "$file" "$SINGBOX_SHA256"
	tar -xzf "$file" "sing-box-$v-linux-amd64-musl/sing-box"
	mv "sing-box-$v-linux-amd64-musl/sing-box" sing-box
	rmdir "sing-box-$v-linux-amd64-musl"
	chmod +x sing-box
	rm -f "$file"
	echo "$SINGBOX_VERSION" > sing-box.version
fi

if [ ! -x mihomo ] || [ "$(cat mihomo.version 2>/dev/null)" != "$MIHOMO_VERSION" ]; then
	file="mihomo-linux-amd64-$MIHOMO_VERSION.gz"
	wget -q -O "$file" "https://github.com/MetaCubeX/mihomo/releases/download/$MIHOMO_VERSION/$file"
	check "$file" "$MIHOMO_SHA256"
	gunzip -c "$file" > mihomo
	chmod +x mihomo
	rm -f "$file"
	echo "$MIHOMO_VERSION" > mihomo.version
fi

./xray version | head -1
./sing-box version | head -3
./mihomo -v | head -1
