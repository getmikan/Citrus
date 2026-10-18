# Server comparison: Xray-core vs sing-box vs mihomo vs Citrus

A reproducible comparison of the **server side** of four cores, each in its
own container, under the same load:

| server | binary | pin |
|---|---|---|
| Xray-core | release `Xray-linux-64.zip` v26.10.17 | SHA-256 `ecdd54eccd24c4c21a8f00968e7dbf7f5996da92383d2321170b560dc4a95158` (the asset digest on GitHub, also checked against the release's `.dgst`) |
| sing-box | release `sing-box-1.14.3-linux-amd64-musl.tar.gz` v1.14.3 (musl: the runtime image is alpine) | SHA-256 `41fc81fd041134d4d7d850a928d7d2cde17a7d6563953f406b22d32a68bfab1f` (the asset digest on GitHub; the release publishes no checksum file) |
| mihomo | release `mihomo-linux-amd64-v1.19.32.gz` | SHA-256 `8451100836c9eda194331c2babfad490b2faf30cebc1a04b0e76fd8ac2d35d10` |
| Citrus | built from this checkout | the flags of the linux-amd64 release build: `GOAMD64=v3 CGO_ENABLED=0 go build -tags with_gvisor -trimpath -ldflags "-extldflags --static -X ... -w -s -buildid="` in `golang:1.26.9` |

The pins live in `fetch.sh`. Results and the interpretation of the runs:
[`results/2026-10-18-four-cores/RESULTS.md`](results/2026-10-18-four-cores/RESULTS.md)
(four cores, nine protocol variants), [`results/2026-10-16/RESULTS.md`](results/2026-10-16/RESULTS.md)
(Xray, mihomo, Citrus on REALITY, XHTTP, Trojan, SS2022).

## Run

```sh
test/bench/compare/run.sh          # about 4 hours with the defaults (3 repetitions)
```

Needs bash and Docker with a Linux engine (Linux, or Git Bash + Docker Desktop
on Windows) and network access for the downloads. Everything runs in
containers: the downloads (`fetch.sh`, in `alpine`), the Citrus build
(`build.sh`, in `golang:1.26.9`, module cache in the `$IMAGE-gomod`
volume), the runtime image `$IMAGE` (`Dockerfile`, alpine with the four
servers, the clients and the `cmp` tool). On Windows the scripts must have LF
line endings in the working tree (`sh` in the containers runs them).

Knobs (environment): `REPS` (3), `PROTOS`, `SERVERS` (`xray singbox mihomo
citrus`), `SKIP` (`server:proto` pairs, default `xray:reality-x25519`), `DUR`
(measured window per phase, 10s), `RAMP` (unmeasured start of each phase,
2s), `IDLE` (`1000,5000`), `SERVER_CPUS` (`2,4`), `CLIENT_CPUS` (`6-19`),
`SINK_CPUS` (`20-27`), `SERVER_MEM` (`2g`), `OUT` (`results/<date>`),
`PHASES` (`mem,hs,bulk,fixed,lat`), `FP` (client uTLS fingerprint of the
REALITY runs, `chrome`), `SETTLE` (memory phase: wait before each reading,
5s), `SKIP_BUILD=1` to reuse the image, `BUILD=host` to build Citrus and
`cmp` with the host's Go instead of in `golang:1.26.9` (CI).

Sharing the host: `NAME` (`cmp`: containers `$NAME-server`, `$NAME-client`,
`$NAME-sink`), `NET` (`citrus-cmp`), `SUBNET` (`10.77.0`, the first three
octets of the /24), `IMAGE` (`citrus-cmp`, also the prefix of the Go cache
volumes) let a second setup run next to another one without touching it.
`ALONE=1` makes every run wait until no other container runs on the host
(our own excepted, and the names matching the extended regex
`ALONE_IGNORE`), and records the waits in `$OUT/waits.txt`; a container that
starts during a run marks it `disturbed` there. The numbers are only valid
with the host otherwise idle: redo such runs with `ONLY` (space-separated run
tags, e.g. `ONLY="citrus-trojan-rep2 xray-ss2022-rep1"`, with the same
`REPS`) into another `OUT` and copy their `runs/*.json` over. Example:
`ALONE=1 ALONE_IGNORE='^(db|web)-' NAME=c4 NET=c4-net SUBNET=10.81.0 IMAGE=c4-cmp test/bench/compare/run.sh`.

A quick smoke run: `PROTOS="trojan hy2" REPS=1 DUR=3s IDLE=200,500 OUT=/tmp/smoke test/bench/compare/run.sh`.

CPU profiles (mihomo and Citrus): `PPROF=1` starts them with `log-level:
debug` and an external controller (secret `bench`), which mounts
`/debug/pprof`; `cmp` turns the level back to `warning` and saves a CPU
profile and a heap-allocation profile (`allocs`, a delta over the window) of
every handshake and bulk window to `$OUT/pprof`. Keep these runs
apart from the reference numbers. Example:
`PPROF=1 PHASES=hs,bulk PROTOS="trojan ss2022" SERVERS="mihomo citrus" REPS=1 OUT=/tmp/prof test/bench/compare/run.sh`,
then `go tool pprof -top /tmp/prof/pprof/citrus-trojan-handshake-cpu.pb.gz`
(or `-sample_index=alloc_space` on `...-handshake-allocs.pb.gz`).

## Layout

```
<SUBNET>.10  <NAME>-server  cpuset 2,4   2 GiB   one of xray / sing-box / mihomo / citrus, fresh per run
<SUBNET>.20  <NAME>-sink    cpuset 20-27         cmp sink: TCP sink :9000, TLS sink :9443, REALITY target :8443
<SUBNET>.30  <NAME>-client  cpuset 6-19  8 GiB   cmp measure + the protocol's client (SOCKS5 127.0.0.1:1080)
```

- Same Docker network for all three, same sysctls
  (`ip_local_port_range 1024 65000`, `tcp_tw_reuse 1`), `nofile` limit and
  `NET_ADMIN` capability (so that the QUIC servers and clients can raise their
  UDP buffers past `net.core.rmem_max` with `SO_RCVBUFFORCE`, as on a real
  host; it changes nothing for TCP).
- The server gets two vCPUs on different virtual cores; their hyperthread
  siblings (3, 5) are left idle. `GOMAXPROCS` is left to the runtime (it sees
  the cpuset: 2).
- **One client per protocol, the same for every server**, driven through its
  SOCKS5 inbound by `cmp measure` in the same container. Xray v26.10.17
  wherever Xray speaks the protocol (REALITY, XHTTP, Trojan, SS2022,
  Hysteria2): it is neither sing-box nor of the mihomo family. sing-box
  v1.14.3 for TUIC and AnyTLS, which Xray lacks. Within a protocol only the
  server changes. The client's CPU (and the sink's) is recorded per window
  and a run is flagged when either goes above 70% of its cpuset.
- `cmp measure` reads the server container's cgroup through the host's
  `/sys/fs/cgroup` (`cpu.stat` for CPU time, `memory.current` and
  `memory.stat`) and the server process's `VmRSS` through `--pid=host`.
- Every run starts a new server container. The order of the servers rotates
  every repetition, so a slow drift of the host does not always hit the same
  server.

## Protocols

All server configs are generated by `cmp gen` (`results/<date>/configs` has
copies with the keys redacted). Same settings on every server; a server
without the inbound is `n/a` (no config, the run is skipped):

| name | inbound | client | servers |
|---|---|---|---|
| `reality` | VLESS + REALITY + `xtls-rprx-vision`, target = the sink's TLS 1.3 server | Xray, fingerprint `chrome` | all four |
| `reality-x25519` | same inbound | Xray, fingerprint `ios` (X25519 key share only); handshake phase only; skipped for Xray, whose REALITY server rejects these ClientHellos | sing-box, mihomo, Citrus |
| `reality-tlsin` | same inbound | like `reality`, but every tunnel carries TLS 1.3 to the sink, so Vision's inner-TLS path is used; bulk and fixed-rate phases only (see below) | all four |
| `xhttp` | VLESS + XHTTP `stream-one`, TLS (h2) | Xray, XHTTP `stream-one`, ALPN h2, default xmux | Xray, mihomo, Citrus (sing-box has no XHTTP) |
| `trojan` | Trojan over TLS | Xray | all four |
| `ss2022` | Shadowsocks `2022-blake3-aes-128-gcm`, one user, TCP | Xray | all four |
| `hy2` | Hysteria2 (QUIC), ALPN h3, no bandwidth hints (BBR) | Xray | all four |
| `tuic` | TUIC v5 (QUIC), ALPN h3, congestion control BBR on both ends | sing-box | sing-box, mihomo, Citrus |
| `anytls` | AnyTLS over TLS, default padding | sing-box | sing-box, mihomo, Citrus |

Before each TCP+TLS run a probe connection goes through a relay that reads the
key share group of the server's ServerHello (`keyshare` in the results).

Hysteria2 and TUIC carry every proxied connection as a stream of one QUIC
connection, and the AnyTLS client reuses idle sessions: on these protocols a
"new connection" in the handshake and latency phases is a new stream (or
session reuse), not a new handshake, and an idle tunnel is an idle stream.

## Phases (per run)

1. Warm-up: 3 s of 8-stream download and 320 short connections.
2. `mem` — idle tunnels: 1000, then 5000 tunnels, each opened with one echo
   round trip, then idle; after 5 s, server RSS and cgroup memory minus the
   baseline, per tunnel. A sample of tunnels is checked to still echo.
3. `hs` — 128 concurrent clients, each in a loop: new tunnel, 1-byte request,
   64-byte answer (the sink closes first). Connections per second, time to
   first byte p50/p99, server CPU per connection, and the rate of the first and
   second half of the window (degradation check).
4. `bulk` — download and upload over 1 stream and over 32 streams, unpaced:
   MB/s (10^6 bytes) and server CPU seconds per 10^9 bytes.
5. `fixed` — one stream paced at 500 Mbit/s (the sink paces downloads, `cmp`
   paces uploads): server CPU seconds per GB and cores busy at the same rate
   for every server.
6. `lat` — echo RTT (64 bytes every 20 ms) on an established tunnel, first on
   an idle server, then while an 8-stream unpaced download runs; plus new
   connections at 10/s during the download (TTFB).

Each phase has an unmeasured ramp, then the window (`DUR`). Output:
`runs/<server>-<proto>-rep<N>.json` (all numbers; `singbox` is sing-box),
`logs/` (server and client logs, container state: OOM, restarts),
`summary.csv` and `tables.md` (median, min–max over the repetitions),
`compact.md` (medians, one cell per protocol: Xray / sing-box / mihomo /
Citrus) and `headline.md` (the main metrics with the winner per protocol: a
tie when the min–max ranges overlap, and Citrus against the best other
server) from `cmp report`, `env.txt`.

`reality-tlsin` and Vision's direct copy: Xray's client switches a tunnel's
upload to direct copy only when one of its reads from the local socket holds
nothing but whole TLS application-data records. The TLS sink therefore
writes one byte once its handshake is done, which `cmp` waits for before it
sends the command (so the client's Finished flight and the command record
are not read together), and acknowledges the upload command with one byte
before `cmp` sends any data (so the command record is read alone). Every
upload stream then goes direct, on every server; without this a stream went
direct or stayed padded (~7� slower) depending on how the reads split. The
Xray client of this protocol logs at debug level, and `cmp measure` counts
per bulk phase the tunnels whose upload and download went direct (`vision`
in the run JSON, a table in `tables.md`, an anomaly when one did not);
`cmp report` ranks the `reality-tlsin` upload metrics only when every upload
stream of every run went direct.

## CI perf check

`.github/workflows/perf-nightly.yml` runs a short version nightly on `dev`
(and on pull requests that touch this directory or the workflow): Citrus and
mihomo only, REALITY, Trojan, SS2022 and Hysteria2, the `mem` (1000 tunnels),
`hs` and `bulk` phases, 2 repetitions of 1 s ramp + 3 s windows, on a 4-vCPU
`ubuntu-latest` runner (server cpuset 0, client 1-2, sink 3). Absolute numbers
of a shared runner drift between runs, so `cmp gate` compares the ratio
Citrus/mihomo of the same job (oriented so that above 1 is Citrus better:
mihomo/Citrus for CPU and memory) against `ci/baseline.json`, and fails when a
ratio falls more than the baseline's `tolerance` (20%) below it, or when
Citrus has no value where mihomo has one. The table is in the job summary,
the run (`runs/`, `tables.md`, `ratios.json` with this run's ratios) in the
`perf-results` artifact. To move the baseline after an intended change, take
the ratios of a few runs (their `ratios.json`) and commit the lower values.

## Caveats

- Docker Desktop runs the containers in a WSL2 VM. The cpusets pin vCPUs, not
  physical cores: Hyper-V may move a vCPU between P- and E-cores of a hybrid
  CPU. The rotation of the server order and the repetitions are there for that;
  read differences within the min–max spread as noise.
- Everything is on one host bridge: no latency, no loss. CPU per GB, CPU per
  connection and memory per tunnel carry over to real nodes better than MB/s.
  For the QUIC protocols this matters most: without loss, congestion control
  barely acts, and one QUIC connection is served by about one core on each
  end, so the client can be the limit even under the 70% flag.
- The servers run with their defaults beyond what the protocol needs (log
  level `warning`/`warn`; Citrus keeps its default per-user traffic accounting
  on).
