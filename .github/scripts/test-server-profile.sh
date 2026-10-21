#!/usr/bin/env bash
# Exercise the real packaged binary with the server image's default UID.
set -euo pipefail
binary=${1:?usage: test-server-profile.sh /path/to/linux-amd64-binary}
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d -t citrus-server-check.XXXXXXXX)
name="citrus-server-check-$(date +%s)-$$"
image="$name:local"
cleanup() {
  if [ "$?" != 0 ]; then docker logs "$name" 2>/dev/null || true; fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm "$name" >/dev/null 2>&1 || true
  docker image rm "$image" >/dev/null 2>&1 || true
  rm -f "$work/Dockerfile.server" "$work/config.yaml" "$work/anonymous-response" "$work/docker/file-name.sh" \
    "$work/docker/server-config.yaml" "$work/bin/version.txt" \
    "$work/bin/citrus-linux-amd64-v1-profile-test.gz"
  rmdir "$work/bin" "$work/docker" "$work"
}
trap cleanup EXIT
mkdir "$work/bin" "$work/docker"
cp "$root/Dockerfile.server" "$work/"
cp "$root/docker/file-name.sh" "$root/docker/server-config.yaml" "$work/docker/"
printf 'profile-test\n' > "$work/bin/version.txt"
gzip -c "$binary" > "$work/bin/citrus-linux-amd64-v1-profile-test.gz"
context=$work
# Also usable from Git Bash on a Windows Docker Desktop host.
if command -v cygpath >/dev/null; then context=$(cygpath -am "$work"); fi
export MSYS_NO_PATHCONV=1
docker build --platform linux/amd64 --build-arg TARGETPLATFORM=linux/amd64 \
  -f "$context/Dockerfile.server" -t "$image" "$context"
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=8m "$image" -t
cat > "$work/config.yaml" <<'YAML'
mixed-port: 18080
allow-lan: true
bind-address: '*'
authentication: [profile:fixture-password]
mode: rule
log-level: warning
dns:
  enable: false
tun:
  enable: false
rules: ['MATCH,DIRECT']
YAML
docker volume create "$name" >/dev/null
docker run -d --name "$name" --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=8m \
  --mount "type=volume,src=$name,dst=/var/lib/citrus" \
  --mount "type=bind,src=$context/config.yaml,dst=/etc/citrus/config.yaml,readonly" \
  -p 127.0.0.1::18080 "$image" -f /etc/citrus/config.yaml >/dev/null
docker exec "$name" sh -ec '
  test "$(id -u)" = 65532
  test "$(id -g)" = 65532
  grep -Eq "^Uid:[[:space:]]+65532[[:space:]]+65532[[:space:]]+65532[[:space:]]+65532$" /proc/1/status
  grep -Eq "^CapEff:[[:space:]]+0+$" /proc/1/status
  grep -Eq "^NoNewPrivs:[[:space:]]+1$" /proc/1/status
  test ! -w /etc/citrus/config.yaml
  test ! -e /dev/net/tun
  ! command -v iptables
  touch /var/lib/citrus/profile-state
'
docker exec -d "$name" sh -ec '
  printf "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 25\r\n\r\ncitrus-server-profile-ok\n" | nc -l -p 18081 -w 30 > /tmp/origin-request
'
binding=$(docker port "$name" 18080/tcp)
proxy="http://127.0.0.1:${binding##*:}"
for attempt in {1..30}; do
  if result=$(curl --silent --show-error --fail --max-time 2 --noproxy '' \
    --proxy "$proxy" --proxy-user profile:fixture-password http://127.0.0.1:18081/); then
    break
  fi
  sleep 0.2
done
test "${result:-}" = citrus-server-profile-ok
status=$(curl --silent --max-time 2 --output "$context/anonymous-response" --write-out '%{http_code}' \
  --noproxy '' --proxy "$proxy" http://127.0.0.1:18081/)
test "$status" = 407
echo 'Server profile: non-root, zero capabilities, read-only root, writable state, authenticated TCP relay passed.'
