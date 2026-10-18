#!/usr/bin/env bash
# Server comparison: Xray-core vs sing-box vs upstream mihomo vs Citrus. One
# command:
#
#   test/bench/compare/run.sh
#
# Needs bash and Docker (Linux engine); works from Git Bash on Windows with
# Docker Desktop. See README.md for the knobs (environment variables below).
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' # Git Bash: keep /paths as they are

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)

REPS=${REPS:-3}
SERVERS=${SERVERS:-"xray singbox mihomo citrus"}
PROTOS=${PROTOS:-"reality reality-x25519 reality-tlsin xhttp trojan ss2022 hy2 tuic anytls"}
# Combinations a server cannot do beyond the inbounds it lacks (those are
# skipped as n/a: cmp gen writes no config for them). Xray's REALITY server
# rejects the Xray client's X25519-only fingerprints ("authentication failed
# or validation criteria not met"), see results/2026-10-16/RESULTS.md.
SKIP=${SKIP:-"xray:reality-x25519"}
DUR=${DUR:-10s}
RAMP=${RAMP:-2s}
IDLE=${IDLE:-1000,5000}
SERVER_CPUS=${SERVER_CPUS:-2,4} # two vCPUs on different (virtual) cores; their siblings stay idle
CLIENT_CPUS=${CLIENT_CPUS:-6-19}
SINK_CPUS=${SINK_CPUS:-20-27}
SERVER_MEM=${SERVER_MEM:-2g}
OUT=${OUT:-$here/results/$(date +%F)}
GO_IMAGE=${GO_IMAGE:-golang:1.26.9}
ALPINE_IMAGE=${ALPINE_IMAGE:-alpine:3.24.2}
# Names of what this script creates, so that two setups can share a host:
# containers $NAME-server, $NAME-client, $NAME-sink; network $NET on
# $SUBNET.0/24; image $IMAGE; Go caches in the volumes $IMAGE-gomod and
# $IMAGE-gocache.
NAME=${NAME:-cmp}
NET=${NET:-citrus-cmp}
SUBNET=${SUBNET:-10.77.0}
IMAGE=${IMAGE:-citrus-cmp}
# ALONE=1: before every run, wait until no other container runs on the host
# besides ours and those matching the extended regex ALONE_IGNORE (names).
ALONE=${ALONE:-}
ALONE_IGNORE=${ALONE_IGNORE:-}

# Docker Desktop on Windows wants C:/... for bind mounts.
hostpath() { (cd "$1" && (pwd -W 2>/dev/null || pwd)); }

build="$here/.build"
mkdir -p "$build/bin" "$build/cfg" "$OUT/runs" "$OUT/logs" "$OUT/configs"

if [ -z "${SKIP_BUILD:-}" ]; then
	echo "== fetch Xray, sing-box and mihomo (pinned, sha256 checked)"
	docker run --rm -v "$(hostpath "$here"):/c" "$ALPINE_IMAGE" sh /c/fetch.sh /c/.build/bin
	echo "== build Citrus (release flags) and cmp"
	ver=$(git -C "$(hostpath "$repo")" rev-parse --short HEAD 2>/dev/null || echo unknown)
	if [ -n "$(git -C "$(hostpath "$repo")" status --porcelain -- . ':!test/bench/compare' 2>/dev/null)" ]; then ver="$ver-dirty"; fi
	if [ "${BUILD:-}" = host ]; then
		# the host's Go (CI: the pinned toolchain of .github/scripts/setup-go.sh)
		CITRUS_VERSION="$ver" SRC="$repo" sh "$here/build.sh" "$build/bin"
	else
		docker run --rm -e CITRUS_VERSION="$ver" \
			-v "$IMAGE-gomod:/go/pkg/mod" -v "$IMAGE-gocache:/root/.cache/go-build" \
			-v "$(hostpath "$repo"):/src" "$GO_IMAGE" sh /src/test/bench/compare/build.sh /src/test/bench/compare/.build/bin
	fi
	cp "$here/Dockerfile" "$build/Dockerfile"
	docker build -q -t "$IMAGE" "$(hostpath "$build")" >/dev/null
fi

server=$NAME-server client=$NAME-client sink=$NAME-sink
cleanup() {
	docker rm -f "$server" "$client" "$sink" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

cfg=$(hostpath "$build/cfg")
out=$(hostpath "$OUT")
rm -rf "$build/cfg"/*
docker run --rm -e CMP_NET="$SUBNET" -v "$cfg:/cfg" -v "$out:/results" "$IMAGE" /opt/bin/cmp gen -out /cfg -redacted /results/configs

# NET_ADMIN lets the QUIC servers and clients (Hysteria2, TUIC) raise their
# UDP socket buffers past net.core.rmem_max (SO_RCVBUFFORCE), as they do on a
# real host; it does not change anything for TCP.
common=(--network "$NET" --ulimit nofile=1048576:1048576 --cap-add NET_ADMIN -e CMP_NET="$SUBNET"
	--sysctl net.ipv4.ip_local_port_range="1024 65000" --sysctl net.ipv4.tcp_tw_reuse=1)

docker run -d --name "$sink" "${common[@]}" --ip "$SUBNET.20" --cpuset-cpus "$SINK_CPUS" --memory 4g \
	-v "$cfg:/cfg:ro" "$IMAGE" /opt/bin/cmp sink -cfg /cfg >/dev/null
# The client reads the server's cgroup (CPU, memory) and /proc (RSS) of the host VM.
docker run -d --name "$client" "${common[@]}" --ip "$SUBNET.30" --cpuset-cpus "$CLIENT_CPUS" --memory 8g \
	--cgroupns=host --pid=host -v /sys/fs/cgroup:/hostcg:ro \
	-v "$cfg:/cfg:ro" -v "$out:/results" "$IMAGE" sleep infinity >/dev/null

cgdir() {
	local id
	id=$(docker inspect -f '{{.Id}}' "$1")
	for d in "/hostcg/docker/$id" "/hostcg/system.slice/docker-$id.scope"; do
		if docker exec "$client" test -d "$d"; then echo "$d"; return; fi
	done
	echo "no cgroup directory for $1" >&2
	exit 1
}
client_cg=$(cgdir "$client")
sink_cg=$(cgdir "$sink")

{
	echo "date: $(date -u +%FT%TZ)"
	echo "citrus: $(docker run --rm "$IMAGE" /opt/bin/citrus -v | head -1)"
	echo "mihomo: $(docker run --rm "$IMAGE" /opt/bin/mihomo -v | head -1)"
	echo "sing-box: $(docker run --rm "$IMAGE" /opt/bin/sing-box version | tr '\n' ' ' | sed 's/  */ /g')"
	echo "xray: $(docker run --rm "$IMAGE" /opt/bin/xray version | head -1)"
	echo "cpu: $(docker run --rm "$IMAGE" sh -c 'grep -m1 "model name" /proc/cpuinfo | cut -d: -f2' | sed 's/^ //')"
	echo "docker: $(docker version --format 'server {{.Server.Version}}, client {{.Client.Version}}')"
	echo "engine: $(docker info --format '{{.OperatingSystem}}, kernel {{.KernelVersion}}, {{.NCPU}} CPUs, {{.MemTotal}} bytes, cgroup v{{.CgroupVersion}} ({{.CgroupDriver}})')"
	echo "cpusets: server $SERVER_CPUS (memory $SERVER_MEM), client $CLIENT_CPUS, sink $SINK_CPUS"
	echo "skip: $SKIP"
	echo "params: reps $REPS, window $DUR, ramp $RAMP, idle $IDLE, protos [$PROTOS], servers [$SERVERS]"
	if [ "${BUILD:-}" = host ]; then echo "images: host $(go version 2>/dev/null | cut -d" " -f3) (build), $ALPINE_IMAGE (runtime)"; else echo "images: $GO_IMAGE (build), $ALPINE_IMAGE (runtime)"; fi
} | tee "$OUT/env.txt"

# server_cfg server proto: the server's config file for the protocol, if it
# has such an inbound (cmp gen writes none otherwise).
server_cfg() {
	local base=${2%-x25519}
	base=${base%-tlsin}
	case $1 in
	xray | singbox) echo "$1/$base.json" ;;
	*) echo "$1/$base$sfx.yaml" ;;
	esac
}

server_cmd() { # server proto
	local f
	f=/cfg/$(server_cfg "$1" "$2")
	case $1 in
	xray) echo "/opt/bin/xray run -c $f" ;;
	singbox) echo "/opt/bin/sing-box run -c $f" ;;
	mihomo) echo "/opt/bin/mihomo -d /tmp -f $f" ;;
	citrus) echo "/opt/bin/citrus -d /tmp -f $f" ;;
	esac
}

others() { # running containers besides ours and ALONE_IGNORE
	docker ps --format '{{.Names}}' | grep -vxE "$server|$client|$sink" |
		{ if [ -n "$ALONE_IGNORE" ]; then grep -vE "$ALONE_IGNORE"; else cat; fi; } || true
}

# Waits until the host runs nothing but our containers (and ALONE_IGNORE).
wait_alone() {
	[ -n "$ALONE" ] || return 0
	local others waited=0
	while :; do
		others=$(others)
		[ -z "$others" ] && break
		if [ $waited = 0 ]; then
			echo "   waiting for other containers to finish: $(echo $others)"
			echo "$(date -u +%FT%TZ) $1 waits for: $(echo $others)" >>"$OUT/waits.txt"
		fi
		waited=$((waited + 10))
		sleep 10
	done
	if [ $waited != 0 ]; then
		echo "$(date -u +%FT%TZ) $1 waited ${waited}s" >>"$OUT/waits.txt"
		sleep 5
	fi
}

# PPROF=1: mihomo and Citrus start with log-level debug (which mounts
# /debug/pprof on the external controller); cmp turns the level back to
# warning and saves a CPU profile of every handshake and bulk window to
# $OUT/pprof. Not for the reference numbers: the controller is extra.
if [ -n "${PPROF:-}" ]; then
	for s in mihomo citrus; do
		for f in "$build/cfg/$s"/*.yaml; do
			sed 's|^  "log-level": "warning",|  "external-controller": "0.0.0.0:9090",\n  "secret": "bench",\n  "log-level": "debug",|' "$f" >"${f%.yaml}-pprof.yaml"
		done
	done
fi

read -r -a servers <<<"$SERVERS"
for rep in $(seq 1 "$REPS"); do
	for proto in $PROTOS; do
		# rotate the server order every repetition, so drift (thermal, the host)
		# does not always hit the same server
		n=${#servers[@]}
		for i in $(seq 0 $((n - 1))); do
			s=${servers[$(((i + rep - 1) % n))]}
			tag="$s-$proto-rep$rep"
			if [ -n "${ONLY:-}" ]; then
				case " $ONLY " in *" $tag "*) ;; *) continue ;; esac
			fi
			case " $SKIP " in *" $s:$proto "*)
				echo "== $tag skipped (SKIP)"
				continue
				;;
			esac
			sfx="" pprof_args=""
			if [ -n "${PPROF:-}" ] && [ "$s" != xray ] && [ "$s" != singbox ]; then
				sfx=-pprof pprof_args="-pprof http://$SUBNET.10:9090 -pprof-secret bench -pprof-dir /results/pprof"
			fi
			if [ ! -f "$build/cfg/$(server_cfg "$s" "$proto")" ]; then
				echo "== $tag n/a (no such inbound)"
				continue
			fi
			wait_alone "$tag"
			echo "== $tag ($(date +%T))"
			# shellcheck disable=SC2046
			docker run -d --name "$server" "${common[@]}" --ip "$SUBNET.10" \
				--cpuset-cpus "$SERVER_CPUS" --memory "$SERVER_MEM" --memory-swap "$SERVER_MEM" \
				-v "$cfg:/cfg:ro" "$IMAGE" $(server_cmd "$s" "$proto") >/dev/null
			server_cg=$(cgdir "$server")
			# ALONE: watch for containers that start during the run
			watch_pid=
			if [ -n "$ALONE" ]; then
				rm -f "$build/others"
				while :; do
					o=$(others)
					[ -n "$o" ] && echo "$o" >>"$build/others"
					sleep 2
				done &
				watch_pid=$!
			fi
			docker exec "$client" /opt/bin/cmp measure -server "$s" -proto "$proto" -rep "$rep" \
				-out "/results/runs/$tag.json" -logs /results/logs \
				-server-cg "$server_cg" -client-cg "$client_cg" -sink-cg "$sink_cg" \
				-dur "$DUR" -ramp "$RAMP" -idle "$IDLE" ${SETTLE:+-settle "$SETTLE"} ${PHASES:+-phases "$PHASES"} ${FP:+-fp "$FP"} $pprof_args ||
				echo "!! $tag failed" | tee -a "$OUT/failures.txt"
			if [ -n "$watch_pid" ]; then
				kill "$watch_pid" 2>/dev/null || true
				wait "$watch_pid" 2>/dev/null || true
				if [ -s "$build/others" ]; then
					echo "!! $tag disturbed by: $(sort -u "$build/others" | tr '\n' ' ')" | tee -a "$OUT/waits.txt"
				fi
			fi
			docker inspect -f 'oom={{.State.OOMKilled}} running={{.State.Running}} restarts={{.RestartCount}} exit={{.State.ExitCode}}' "$server" >"$OUT/logs/$tag-server.state"
			docker logs "$server" >"$OUT/logs/$tag-server.log" 2>&1 || true
			docker rm -f "$server" >/dev/null
			sleep 2
		done
	done
done

docker exec "$client" /opt/bin/cmp report -dir /results
echo "results in $OUT"
