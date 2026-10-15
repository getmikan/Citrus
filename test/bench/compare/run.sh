#!/usr/bin/env bash
# Server comparison: Xray-core vs upstream mihomo vs Citrus. One command:
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
SERVERS=${SERVERS:-"xray mihomo citrus"}
PROTOS=${PROTOS:-"reality reality-x25519 reality-tlsin xhttp trojan ss2022"}
# Combinations a server cannot do. Xray v26.10.10's REALITY server rejects the
# Xray client's X25519-only fingerprints ("authentication failed or validation
# criteria not met"), see RESULTS.md.
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
NET=citrus-cmp

# Docker Desktop on Windows wants C:/... for bind mounts.
hostpath() { (cd "$1" && (pwd -W 2>/dev/null || pwd)); }

build="$here/.build"
mkdir -p "$build/bin" "$build/cfg" "$OUT/runs" "$OUT/logs" "$OUT/configs"

if [ -z "${SKIP_BUILD:-}" ]; then
	echo "== fetch Xray and mihomo (pinned, sha256 checked)"
	docker run --rm -v "$(hostpath "$here"):/c" "$ALPINE_IMAGE" sh /c/fetch.sh /c/.build/bin
	echo "== build Citrus (release flags) and cmp"
	ver=$(git -C "$(hostpath "$repo")" rev-parse --short HEAD 2>/dev/null || echo unknown)
	if [ -n "$(git -C "$(hostpath "$repo")" status --porcelain -- . ':!test/bench/compare' 2>/dev/null)" ]; then ver="$ver-dirty"; fi
	docker run --rm -e CITRUS_VERSION="$ver" \
		-v citrus-cmp-gomod:/go/pkg/mod -v citrus-cmp-gocache:/root/.cache/go-build \
		-v "$(hostpath "$repo"):/src" "$GO_IMAGE" sh /src/test/bench/compare/build.sh /src/test/bench/compare/.build/bin
	cp "$here/Dockerfile" "$build/Dockerfile"
	docker build -q -t citrus-cmp "$(hostpath "$build")" >/dev/null
fi

cleanup() {
	docker rm -f cmp-server cmp-client cmp-sink >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create --subnet 10.77.0.0/24 "$NET" >/dev/null

cfg=$(hostpath "$build/cfg")
out=$(hostpath "$OUT")
rm -rf "$build/cfg"/*
docker run --rm -v "$cfg:/cfg" -v "$out:/results" citrus-cmp /opt/bin/cmp gen -out /cfg -redacted /results/configs

common=(--network "$NET" --ulimit nofile=1048576:1048576
	--sysctl net.ipv4.ip_local_port_range="1024 65000" --sysctl net.ipv4.tcp_tw_reuse=1)

docker run -d --name cmp-sink "${common[@]}" --ip 10.77.0.20 --cpuset-cpus "$SINK_CPUS" --memory 4g \
	-v "$cfg:/cfg:ro" citrus-cmp /opt/bin/cmp sink -cfg /cfg >/dev/null
# The client reads the server's cgroup (CPU, memory) and /proc (RSS) of the host VM.
docker run -d --name cmp-client "${common[@]}" --ip 10.77.0.30 --cpuset-cpus "$CLIENT_CPUS" --memory 8g \
	--cgroupns=host --pid=host -v /sys/fs/cgroup:/hostcg:ro \
	-v "$cfg:/cfg:ro" -v "$out:/results" citrus-cmp sleep infinity >/dev/null

cgdir() {
	local id
	id=$(docker inspect -f '{{.Id}}' "$1")
	for d in "/hostcg/docker/$id" "/hostcg/system.slice/docker-$id.scope"; do
		if docker exec cmp-client test -d "$d"; then echo "$d"; return; fi
	done
	echo "no cgroup directory for $1" >&2
	exit 1
}
client_cg=$(cgdir cmp-client)
sink_cg=$(cgdir cmp-sink)

{
	echo "date: $(date -u +%FT%TZ)"
	echo "citrus: $(docker run --rm citrus-cmp /opt/bin/citrus -v | head -1)"
	echo "mihomo: $(docker run --rm citrus-cmp /opt/bin/mihomo -v | head -1)"
	echo "xray: $(docker run --rm citrus-cmp /opt/bin/xray version | head -1)"
	echo "cpu: $(docker run --rm citrus-cmp sh -c 'grep -m1 "model name" /proc/cpuinfo | cut -d: -f2' | sed 's/^ //')"
	echo "docker: $(docker version --format 'server {{.Server.Version}}, client {{.Client.Version}}')"
	echo "engine: $(docker info --format '{{.OperatingSystem}}, kernel {{.KernelVersion}}, {{.NCPU}} CPUs, {{.MemTotal}} bytes, cgroup v{{.CgroupVersion}} ({{.CgroupDriver}})')"
	echo "cpusets: server $SERVER_CPUS (memory $SERVER_MEM), client $CLIENT_CPUS, sink $SINK_CPUS"
	echo "skip: $SKIP"
	echo "params: reps $REPS, window $DUR, ramp $RAMP, idle $IDLE, protos [$PROTOS], servers [$SERVERS]"
	echo "images: $GO_IMAGE (build), $ALPINE_IMAGE (runtime)"
} | tee "$OUT/env.txt"

server_cmd() { # server proto
	local base=${2%-x25519}
	base=${base%-tlsin}
	case $1 in
	xray) echo "/opt/bin/xray run -c /cfg/xray/$base.json" ;;
	mihomo) echo "/opt/bin/mihomo -d /tmp -f /cfg/mihomo/$base$sfx.yaml" ;;
	citrus) echo "/opt/bin/citrus -d /tmp -f /cfg/citrus/$base$sfx.yaml" ;;
	esac
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
			case " $SKIP " in *" $s:$proto "*)
				echo "== $tag skipped (SKIP)"
				continue
				;;
			esac
			echo "== $tag ($(date +%T))"
			sfx="" pprof_args=""
			if [ -n "${PPROF:-}" ] && [ "$s" != xray ]; then
				sfx=-pprof pprof_args="-pprof http://10.77.0.10:9090 -pprof-secret bench -pprof-dir /results/pprof"
			fi
			# shellcheck disable=SC2046
			docker run -d --name cmp-server "${common[@]}" --ip 10.77.0.10 \
				--cpuset-cpus "$SERVER_CPUS" --memory "$SERVER_MEM" --memory-swap "$SERVER_MEM" \
				-v "$cfg:/cfg:ro" citrus-cmp $(server_cmd "$s" "$proto") >/dev/null
			server_cg=$(cgdir cmp-server)
			docker exec cmp-client /opt/bin/cmp measure -server "$s" -proto "$proto" -rep "$rep" \
				-out "/results/runs/$tag.json" -logs /results/logs \
				-server-cg "$server_cg" -client-cg "$client_cg" -sink-cg "$sink_cg" \
				-dur "$DUR" -ramp "$RAMP" -idle "$IDLE" ${PHASES:+-phases "$PHASES"} ${FP:+-fp "$FP"} $pprof_args ||
				echo "!! $tag failed" | tee -a "$OUT/failures.txt"
			docker inspect -f 'oom={{.State.OOMKilled}} running={{.State.Running}} restarts={{.RestartCount}} exit={{.State.ExitCode}}' cmp-server >"$OUT/logs/$tag-server.state"
			docker logs cmp-server >"$OUT/logs/$tag-server.log" 2>&1 || true
			docker rm -f cmp-server >/dev/null
			sleep 2
		done
	done
done

docker exec cmp-client /opt/bin/cmp report -dir /results
echo "results in $OUT"
