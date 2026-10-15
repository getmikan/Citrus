# Server comparison, 2026-10-16: Xray-core v26.10.10, mihomo v1.19.32, Citrus `c61fd39a`

The runs took place on 2026-10-15 (UTC, see `env.txt`); the directory carries the planned report date.
How to reproduce: [`../../README.md`](../../README.md) (`test/bench/compare/run.sh`).
The raw numbers are in `runs/*.json` (one file per server × protocol ×
repetition), `summary.csv` (every metric: median, min, max, all values) and
`tables.md` (all metrics as tables). Environment: `env.txt`. Configs (keys
redacted): `configs/`. Server and client logs, container state (OOM, restarts):
`logs/`. CPU profiles: `pprof/`.

## Setup

| | |
|---|---|
| Host | Windows 11, Docker Desktop 29.3.1 (Linux engine in WSL2, kernel 6.6.87.2-microsoft-standard-WSL2, cgroup v2), 28 vCPUs, 31 GiB |
| CPU | Intel Core i7-14700K (hybrid: 8 P-cores with HT + 12 E-cores; the VM shows 14 cores × 2 threads) |
| Xray | `Xray-linux-64.zip` v26.10.10 (go1.27.2), SHA-256 `72a5fde8…28e5d9` checked against the pin and the release's `.dgst` |
| mihomo | `mihomo-linux-amd64-v1.19.32.gz` (go1.26.8), SHA-256 `8451100…2d35d10` checked against the pin |
| Citrus | `c61fd39a` (this branch's base, `dev`), built like the linux-amd64 release: go1.26.9, `GOAMD64=v3 CGO_ENABLED=0`, `-tags with_gvisor -trimpath -ldflags "-extldflags --static … -w -s -buildid="` |
| Server container | vCPUs 2 and 4 (two different virtual cores, siblings 3 and 5 left idle), 2 GiB, `GOMAXPROCS` default (2) |
| Client container | vCPUs 6–19, Xray v26.10.10 as the client for every server (SOCKS5 inbound) + `cmp measure` |
| Sink container | vCPUs 20–27: TCP sink, TLS sink, REALITY target (TLS 1.3, `h2`/`http/1.1`) |
| Runs | 3 repetitions; every run a fresh server container; server order rotated every repetition; 2 s ramp + 10 s window per phase |

**Why Xray as the client:** it speaks all four protocols, and it is not one of
the two mihomo-family servers being compared, so it cannot favour Citrus over
mihomo. One client for every server means that within a protocol only the
server changes. Its container never went above 55% of its 14 vCPUs in any
measured window (table "client-container CPU" below), the sink stayed under
70% except in one window flagged below.

## What could not be run

- **Xray server + classic X25519 REALITY.** Xray's REALITY server v26.10.10
  rejected every connection from the Xray client with an X25519-only
  fingerprint (`ios`, `edge`, `qq` tried): *"REALITY: processed invalid
  connection … authentication failed or validation criteria not met"*. With
  fingerprints that offer X25519MLKEM768 (`chrome`, `firefox`, `safari`,
  `randomized`) it works. So:
  - `reality` (the main REALITY runs, fingerprint `chrome`) negotiated
    **X25519MLKEM768 on all three servers** (checked per run by a relay that
    reads the ServerHello key share). This is the ML-KEM comparison, and all
    three servers do it.
  - `reality-x25519` (fingerprint `ios`, key share X25519 only, handshake phase
    only) covers mihomo and Citrus; Xray is skipped.
- Trojan and XHTTP over TLS also negotiated X25519MLKEM768 everywhere (Xray's
  default TLS fingerprint). Shadowsocks 2022 has no TLS.
- Everything else ran on all three servers. No run lost a server process, no
  OOM, no restarts (`logs/*.state`).

## Summary

Within a protocol, differences inside the min–max spread are noise. Spreads
are 1–5% for most metrics (see the tables).

**Citrus vs mihomo** (same code base; Citrus = mihomo + our changes):

- *Throughput and CPU per GB*: the same on REALITY, Trojan and SS2022 (all
  differences inside the spread). XHTTP: Citrus is better on the 32-stream
  download (1267 vs 1198 MB/s, 1.47 vs 1.59 CPU s/GB, ranges disjoint) and
  clearly cheaper on paced upload (3.28 vs 4.03 CPU s/GB at 500 Mbit/s, −19%),
  slightly worse on paced download (4.58 vs 4.38, +5%, ranges disjoint).
- *Memory*: Citrus uses the least memory per idle tunnel of the three:
  REALITY 54 KiB vs 72 (mihomo) and 70 (Xray), Trojan 52 vs 63 and 79. On
  XHTTP and SS2022 Citrus and mihomo are equal (57/58, 52/53 KiB), Xray uses
  more (66, 65). The idle baseline is also lower (~43 MiB vs ~50 and ~56).
- *New connections*: **Citrus is 5–9% slower than mihomo on every protocol**
  and spends 5–8% more server CPU per connection (ranges disjoint in all five
  protocols). See "Follow-ups" for the profile.
- *Latency*: the same as mihomo within the spread.

**Citrus vs Xray:**

- *Download*: Citrus is faster and cheaper on every protocol: 32 streams
  REALITY 2892 vs 2119 MB/s, Trojan 2880 vs 2202, SS2022 3987 vs 2016, XHTTP
  1267 vs 989; at 500 Mbit/s Citrus needs 1.39 vs 2.12 CPU s/GB (Trojan),
  1.35 vs 2.09 (SS2022), 1.47 vs 1.68 (REALITY).
- *Upload*: **Xray is much faster on Trojan and SS2022**: 32 streams 3490 vs
  1922 MB/s and 3470 vs 1874, at 0.53 vs 1.00 CPU s/GB; single stream 1154 vs
  787 and 1258 vs 760. On REALITY + Vision upload they are equal (1907/1909
  MB/s, 1.00/1.01 CPU s/GB); on XHTTP Citrus is ahead (1657 vs 1253). At a
  paced 500 Mbit/s the upload cost is the same for all three (≈1.9 CPU s/GB),
  so Xray's advantage appears only when the server is loaded. The Citrus
  profile of that phase explains it (Follow-ups, 2).
- *New connections*: Xray is faster on REALITY (3615 vs 3057 conn/s, 0.537 vs
  0.622 CPU ms per connection) and slightly on SS2022 (9883 vs 9534); Citrus
  is faster on Trojan (5138 vs 4596) and XHTTP (10149 vs 9100). Xray has the
  longest p99 time to first byte in the handshake phase on Trojan, XHTTP and
  SS2022 (80/52/51 ms vs 50/29/27 for Citrus).
- *Memory*: Citrus lower on every protocol (above). Xray's RSS after an XHTTP
  run stays at ~380 MiB until the end of the run, after its tunnels are
  closed; the other servers and protocols fall back to 60–130 MiB (field
  `rss_end` in the runs).
- *Latency under load*: on TCP-based protocols every server queues the probe
  behind the bulk transfer once its 2 cores are saturated (echo RTT p50 65–80
  ms, p99 130–150 ms); Xray is a little lower on Trojan (66 vs 79 ms) while
  moving 24% less bulk data, a little higher on SS2022 (80 vs 71 ms). On
  XHTTP Citrus and mihomo keep the probe at ~1 ms and new connections at ~3
  ms, Xray at 5.6 ms and 9.6 ms.

**Vision with TLS inside** (`reality-tlsin`, the normal case of Vision in
production): mihomo and Citrus reach the direct-copy path on the 32-stream
download (9.4–9.6 GB/s at 0.20 CPU s/GB); Xray's server did not in this setup
(1270 MB/s, 1.39 CPU s/GB). The single-stream upload is bimodal on every
server: either ~400 MB/s at 2.1–2.8 CPU s/GB, or 2–3 GB/s at 0.1–0.3 (see
"Anomalies").

## Tables

Medians of 3 runs, each cell **Xray / mihomo / Citrus**. MB/s = 10^6 bytes
per second; CPU s/GB = server CPU seconds per 10^9 bytes relayed; TTFB = time
to the first byte of the answer, measured from the SOCKS dial. The min–max
range of every value is in [`tables.md`](tables.md) (one table per metric) and
[`summary.csv`](summary.csv); this file is [`compact.md`](compact.md).

#### Throughput, MB/s

| protocol | dl 1 stream, MB/s | ul 1 stream, MB/s | dl 32 streams, MB/s | ul 32 streams, MB/s |
|---|---|---|---|---|
| reality | 1081 / 1223 / 1189 | 794 / 795 / 806 | 2119 / 2926 / 2892 | 1907 / 1932 / 1909 |
| reality-tlsin | 2012 / 2551 / 1996 | 416 / 1955 / 396 | 1270 / 9633 / 9425 | 2477 / 5387 / 7204 |
| xhttp | 396 / 368 / 368 | 562 / 451 / 516 | 989 / 1198 / 1267 | 1253 / 1565 / 1657 |
| trojan | 1195 / 1215 / 1198 | 1154 / 798 / 787 | 2202 / 2883 / 2880 | 3490 / 1923 / 1922 |
| ss2022 | 1044 / 1767 / 1796 | 1258 / 767 / 760 | 2016 / 4074 / 3987 | 3470 / 1873 / 1874 |

#### Server CPU, CPU seconds per GB

| protocol | dl 32 streams, CPU s/GB | ul 32 streams, CPU s/GB | dl @500 Mbit/s, CPU s/GB | ul @500 Mbit/s, CPU s/GB |
|---|---|---|---|---|
| reality | 0.90 / 0.66 / 0.66 | 1.00 / 1.00 / 1.01 | 1.68 / 1.43 / 1.47 | 1.87 / 1.89 / 1.95 |
| reality-tlsin | 1.39 / 0.20 / 0.20 | 0.76 / 0.35 / 0.25 | 0.95 / 0.99 / 1.01 | 1.10 / 1.10 / 1.11 |
| xhttp | 2.01 / 1.59 / 1.47 | 1.56 / 1.25 / 1.17 | 5.14 / 4.38 / 4.58 | 4.89 / 4.03 / 3.28 |
| trojan | 0.87 / 0.66 / 0.66 | 0.53 / 1.00 / 1.00 | 2.12 / 1.40 / 1.39 | 1.90 / 1.89 / 1.88 |
| ss2022 | 0.95 / 0.47 / 0.47 | 0.54 / 1.03 / 1.03 | 2.09 / 1.27 / 1.35 | 1.96 / 1.94 / 1.96 |

#### New connections

| protocol | rate, conn/s | TTFB p50, ms | TTFB p99, ms | server CPU per conn, CPU ms |
|---|---|---|---|---|
| reality | 3615 / 3237 / 3057 | 32.9 / 39.6 / 41.8 | 72.7 / 62.2 / 68.6 | 0.537 / 0.592 / 0.622 |
| reality-x25519 | – / 4063 / 3876 | – / 31.4 / 33.1 | – / 50.0 / 49.8 | – / 0.475 / 0.497 |
| xhttp | 9100 / 10865 / 10149 | 11.9 / 10.9 / 11.8 | 51.7 / 28.1 / 28.8 | 0.218 / 0.181 / 0.195 |
| trojan | 4596 / 5676 / 5138 | 24.1 / 21.9 / 23.9 | 79.7 / 45.6 / 49.9 | 0.430 / 0.339 / 0.366 |
| ss2022 | 9883 / 10095 / 9534 | 10.8 / 12.5 / 13.2 | 51.2 / 24.3 / 26.5 | 0.200 / 0.189 / 0.200 |

#### Idle tunnels

| protocol | RSS per tunnel @5000, KiB | RSS per added tunnel 1000→5000, KiB | cgroup memory per tunnel @5000, KiB | RSS @5000, MiB |
|---|---|---|---|---|
| reality | 70.1 / 72.4 / 53.9 | 74.3 / 72.6 / 54.7 | 75.8 / 78.2 / 59.7 | 396.9 / 405.5 / 306.7 |
| xhttp | 65.9 / 58.0 / 56.8 | 69.9 / 60.0 / 58.0 | 70.0 / 62.2 / 60.8 | 375.1 / 333.6 / 321.0 |
| trojan | 79.2 / 62.8 / 51.6 | 84.9 / 65.8 / 52.9 | 84.8 / 68.3 / 57.2 | 447.9 / 356.0 / 293.5 |
| ss2022 | 64.6 / 52.6 / 52.1 | 66.4 / 51.7 / 52.9 | 70.5 / 58.4 / 58.0 | 375.0 / 306.8 / 297.8 |

#### Latency

| protocol | echo RTT idle p50, ms | echo RTT under load p50, ms | echo RTT under load p99, ms | new conn TTFB under load p50, ms | bulk alongside, MB/s |
|---|---|---|---|---|---|
| reality | 0.42 / 0.42 / 0.42 | 74.92 / 80.19 / 80.26 | 141.98 / 143.96 / 146.67 | 290.23 / 314.58 / 312.12 | 2190 / 2863 / 2913 |
| xhttp | 0.50 / 0.53 / 0.54 | 5.58 / 1.34 / 1.08 | 15.02 / 20.62 / 18.17 | 9.59 / 2.73 / 2.71 | 991 / 1177 / 866 |
| trojan | 0.43 / 0.43 / 0.42 | 65.74 / 79.06 / 79.23 | 132.33 / 144.19 / 146.87 | 167.91 / 156.60 / 154.59 | 2175 / 2825 / 2877 |
| ss2022 | 0.41 / 0.42 / 0.41 | 80.32 / 70.57 / 71.10 | 139.53 / 145.13 / 142.46 | 163.22 / 106.86 / 106.23 | 2022 / 4030 / 3973 |

All metrics with full ranges, including the 1000-tunnel step, single-stream
CPU per GB and the bottleneck check: [`tables.md`](tables.md).

## Interpretation and likely reasons

1. **Per-connection cost, Citrus vs mihomo (+5–8% CPU per connection).**
   CPU profiles of the handshake window (`pprof/`, taken in a separate run
   with the controller enabled, so not used for the numbers above):
   SS2022 182 vs 171 µs of CPU per connection, Trojan 365 vs 331 µs. The
   syscall mix (connect, write, read, close, shutdown) is the same. Per
   connection, Citrus spends more in allocation and GC: `runtime.mallocgc`
   32.5 vs 23.3 µs (SS2022), GC assists 7.3 vs 2.3 µs, goroutine stack growth
   (`runtime.adjustframe` and `getStackMap`, Trojan) 18 vs 7 µs, and in the
   traffic tracker (`tcpTracker.Close` 4.8 vs 3.2 µs: per-user and per-inbound
   accounting, the admission release). The relay also goes through Citrus's
   own copy loop (`common/net.copyConn` / `copyAdaptive`, the small idle
   buffer of PR 52), which starts every connection on a 2 KiB buffer and
   switches to pool buffers, i.e. more allocations for a short connection. No
   single hot spot; this is the sum of the per-connection bookkeeping Citrus
   added. A heap-allocation profile of the connection phase is the next step
   (follow-up 1).
2. **Upload under load, Citrus/mihomo vs Xray (2× CPU per GB on Trojan and
   SS2022).** In the Citrus profile of the 32-stream Trojan upload, 64% of the
   server's CPU is in `write(2)` to the destination and 16% in `read(2)`; AES-GCM
   is 10%. The copy loop writes every buffer it reads — one decrypted TLS
   record (≤16 KiB) or AEAD chunk — to the outbound socket with its own
   `write(2)`, and on this bridge each write carries the whole delivery to
   the sink. Xray most likely gathers several records into one multi-buffer
   write (we did not profile Xray): that fits its cost per GB dropping only
   when the server is loaded, and being the same as ours at a paced 500
   Mbit/s, when one record at a time is waiting. Upstream mihomo has the same
   path (same numbers). Batching the writes to the outbound in the upload
   direction is the likely fix (follow-up 2). In the download direction it is
   the other way round: Citrus/mihomo are 28–98% faster than Xray.
3. **REALITY handshake, Xray faster (0.537 vs 0.592 / 0.622 CPU ms).** In the
   Citrus profile of the REALITY handshake window, `x25519ScalarMult` is 16% of
   the server's CPU. Of that, 0.78 s per 10 s window (≈24 µs per connection,
   ~4% of a REALITY connection's CPU) is `ecdh.NewPrivateKey` called from
   `curve25519.X25519` in `utls.RealityServer.func1`: the server's static
   X25519 public key is recomputed from the private key on every connection
   before the shared secret is computed. This is the recompute we already know
   about in getmikan/utls `reality.go` (~line 449); upstream mihomo's profile
   shows the same (0.84 s per window). Caching the static key would remove
   that share. The rest of the gap to Xray is the TLS 1.3 server handshake
   itself (ML-KEM encapsulation, key schedule) in the `utls` fork vs Go's
   standard library in Xray (go1.27.2).
4. **XHTTP**: Citrus's upload path is cheaper than mihomo's (−19% CPU per GB
   at 500 Mbit/s, −6% at 32 streams, the latter inside mihomo's spread) and
   its 32-stream download is 6% faster; this matches our changes to the XHTTP
   server (h2 write batching, upload queue). The paced download is 5% more
   expensive than mihomo's (4.58 vs 4.38, ranges disjoint) — small, but it is
   the one XHTTP number that went the other way.
5. **Memory**: Citrus's lower per-tunnel memory on REALITY and Trojan (−26%
   and −18% vs mihomo) is what PR 52 (idle buffers) set out to do: the relay
   waits for data on a 2 KiB buffer instead of holding a 32 KiB pool buffer
   per idle direction, and Vision's first packets no longer pin one either.
   On SS2022 and XHTTP the difference is inside the spread: there the
   protocol layer keeps its own per-connection buffers (the AEAD reader and
   writer, h2 streams on shared connections), which the relay change does not
   touch.
6. **Fixed-rate CPU**: at 500 Mbit/s on one stream the servers keep 0.06–0.32
   cores busy; Citrus and mihomo are equal within the spread on every
   protocol except XHTTP (above), Xray costs 12–55% more on download.

## Anomalies

- **Vision single-stream upload is bimodal** (`reality-tlsin`, `ul1`):
  either ~400 MB/s with the server at 1.1 cores (2.1–2.8 CPU s/GB), or 2–3
  GB/s at 0.1–0.3 CPU s/GB (the direct-copy path). Occurrences of the fast
  mode, over the main run and the two supplementary runs (`vision-upload/`,
  `vision-upload-b/`, bulk phases only): mihomo 3 of 11 runs, Xray 2 of 11,
  Citrus 1 of 10. The difference between the servers is not significant with
  these counts; it looks like a race in when Vision switches the uplink to
  direct copy. Worth a look on its own (follow-up 4): the slow mode costs
  2–3× the CPU of plain REALITY upload. The `reality-tlsin` medians of
  `ul1` in the tables are therefore not a server comparison.
- In one `reality-tlsin` run (mihomo, rep 3) the sink was at 91% of its CPUs in
  the 32-stream download window; that 12.6 GB/s maximum is sink-bound.
- Xray's RSS stays at ~380 MiB after its XHTTP runs (above).
- One of 32 download streams ended early with `unexpected EOF` on
  `reality-tlsin`: in a short smoke run (3 s windows, sink on 4 vCPUs and
  saturated) once for mihomo and once for Citrus, and once for mihomo in each
  supplementary Vision run. Not seen in the main run, never on Xray (whose
  server did not reach direct copy on download). The downloads with TLS
  inside push 8–12 GB/s through the sink; we did not find the cause.
- Supplementary Vision run (`vision-upload/`): 4 runs failed to start because
  an Xray client from an earlier run still held the SOCKS port; `cmp` now
  kills a leftover client before it starts one (`vision-upload-b/` is the
  rerun).
- Handshake rate did not drop within any 10 s window (first half vs second
  half, field `rate_first_half` / `rate_second_half`), and the repetitions do
  not trend: no server degraded over time.

## Follow-ups for Citrus (no production code changed in this PR)

1. Per-connection overhead vs mihomo (+5–8% CPU per connection): take an
   `allocs` profile of the handshake phase for Citrus and mihomo and diff
   `alloc_space` per connection; candidates are the tracker's user binding /
   admission and per-connection metrics. Profiles: `pprof/*-handshake-cpu.pb.gz`.
2. Upload direction: batch writes to the outbound (vectorised writes or
   reading all buffered records before a write) in the relay for TLS and
   AEAD inbounds. Expected effect on this setup: up to ~2× less CPU per GB
   for Trojan and SS2022 upload under load (Xray's figure). Profile:
   `pprof/citrus-trojan-up32-cpu.pb.gz`.
3. REALITY: cache the static key in getmikan/utls (the per-connection
   `ecdh.NewPrivateKey` from `curve25519.X25519`, ~24 µs per connection on
   this CPU). Profile: `pprof/citrus-reality-handshake-cpu.pb.gz`.
4. Vision uplink direct copy: find why a single upload stream with TLS inside
   sometimes stays on the slow path (all three servers).

## Caveats

- WSL2 vCPUs are not pinned to physical cores: Hyper-V can run the server's
  two vCPUs on P- or E-cores, and the host had other (idle) containers. This
  is why the order rotates and why only differences outside the min–max range
  are called differences. Three repetitions are few; treat differences under
  ~5% with disjoint ranges as "probably real, small".
- One Docker bridge, no latency or loss: MB/s are upper bounds; CPU per GB,
  CPU per connection and memory per tunnel transfer better to real nodes.
- The client also runs REALITY/TLS handshakes; it stayed under 55% of its 14
  vCPUs, so the server was the limit in every window (the handshake windows
  had the server at 1.87–1.99 of 2 cores).
- The servers ran with their defaults apart from the inbound (log level
  `warning`); Citrus keeps its default per-user accounting.
- Xray-linux-64 is built for `GOAMD64=v1`, mihomo and Citrus for `v3`; the
  hot crypto (AES-GCM, X25519, ML-KEM) is assembly or runtime-dispatched and
  does not depend on it.
- The profiles come from separate runs with the controller enabled (mihomo
  and Citrus only; Xray has no comparable endpoint) and are for attribution,
  not for the numbers in the tables.
