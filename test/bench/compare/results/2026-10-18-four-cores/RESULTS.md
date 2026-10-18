# Four cores, server side: Xray-core v26.10.17, sing-box v1.14.3, mihomo v1.19.32, Citrus `cc48b139`

Runs: 2026-10-17 18:40 – 2026-10-18 UTC (see `env.txt`, `env-rerun*.txt`).
How to reproduce: [`../../README.md`](../../README.md) (`test/bench/compare/run.sh`).
Raw numbers: `runs/*.json` (one file per server × protocol × repetition;
`singbox` is sing-box), `summary.csv` (every metric: median, min, max, all
values), `tables.md` (all metrics, median and min–max), `headline.md` (the
main metrics with the winner per protocol), `compact.md` (medians only).
Configs (keys redacted): `configs/`. Logs and container state: `logs/`.
Runs discarded because another container ran on the host meanwhile:
`disturbed/` (see "Runs redone").

## Setup

| | |
|---|---|
| Host | Windows 11, Docker Desktop 29.3.1 (Linux engine in WSL2, kernel 6.6.87.2-microsoft-standard-WSL2, cgroup v2), 28 vCPUs, 31 GiB |
| CPU | Intel Core i7-14700K (hybrid: 8 P-cores with HT + 12 E-cores; the VM shows 14 cores × 2 threads) |
| Xray-core | [v26.10.17](https://github.com/XTLS/Xray-core/releases/tag/v26.10.17), `Xray-linux-64.zip` (go1.27.2, commit `92ccc93`), SHA-256 `ecdd54ec…4a95158` = the asset digest and the release's `.dgst`. Xray marks every release since v26.3.27 as a pre-release; v26.10.17 is the newest one (the previous run used v26.10.10). |
| sing-box | [v1.14.3](https://github.com/SagerNet/sing-box/releases/tag/v1.14.3) (latest stable), `sing-box-1.14.3-linux-amd64-musl.tar.gz` (go1.26.8, revision `7054cac5`, the release's default tags incl. `with_quic`, `with_utls`), SHA-256 `41fc81fd…68bfab1f` = the asset digest on GitHub (no checksum file is published) |
| mihomo | [v1.19.32](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.32) (latest stable), `mihomo-linux-amd64-v1.19.32.gz` (go1.26.8), SHA-256 `84511008…2d35d10` |
| Citrus | `cc48b139` = `dev` after PR #119 (upload write batching) and #118 (fewer allocations per new connection), before #124 (download batching, tls/utls fork bumps), which these numbers do not include; the last reruns ran a build of `cf20ab88` (this branch: same Citrus code, only the harness differs). Built like the linux-amd64 release: go1.26.9, `GOAMD64=v3 CGO_ENABLED=0`, `-tags with_gvisor -trimpath -ldflags "-extldflags --static … -w -s -buildid="` |
| Server container | vCPUs 2 and 4 (two different virtual cores, siblings 3 and 5 idle), 2 GiB, `GOMAXPROCS` default (2) |
| Client container | vCPUs 6–19: the protocol's client (SOCKS5 inbound) + `cmp measure` |
| Sink container | vCPUs 20–27: TCP sink, TLS sink, REALITY target (TLS 1.3, `h2`/`http/1.1`) |
| Runs | 3 repetitions; every run a fresh server container; the server order rotates every repetition; 2 s ramp + 10 s window per phase |

### Protocols, clients, n/a

One client per protocol, the same binary and config for every server, so that
within a protocol only the server changes:

| protocol | client | Xray | sing-box | mihomo | Citrus |
|---|---|---|---|---|---|
| `reality`: VLESS + REALITY + Vision, uTLS `chrome` | Xray v26.10.17 | ✓ | ✓ | ✓ | ✓ |
| `reality-x25519`: same, uTLS `ios` (X25519 only), handshake phase only | Xray | n/a¹ | ✓ | ✓ | ✓ |
| `reality-tlsin`: same as `reality`, TLS 1.3 inside every tunnel (Vision's direct-copy path), bulk + fixed-rate only | Xray | ✓ | ✓ | ✓ | ✓ |
| `xhttp`: VLESS + XHTTP `stream-one`, TLS h2 | Xray | ✓ | n/a (no XHTTP) | ✓ | ✓ |
| `trojan`: Trojan over TLS | Xray | ✓ | ✓ | ✓ | ✓ |
| `ss2022`: Shadowsocks `2022-blake3-aes-128-gcm`, TCP | Xray | ✓ | ✓ | ✓ | ✓ |
| `hy2`: Hysteria2, ALPN h3, no bandwidth hints (BBR) | Xray | ✓² | ✓ | ✓ | ✓ |
| `tuic`: TUIC v5, ALPN h3, BBR on both ends | sing-box v1.14.3 | n/a (no TUIC) | ✓ | ✓ | ✓ |
| `anytls`: AnyTLS over TLS, default padding | sing-box v1.14.3 | n/a (no AnyTLS) | ✓ | ✓ | ✓ |

¹ Xray's REALITY server rejects X25519-only ClientHellos of its own client
(as in `../2026-10-16/RESULTS.md`).
² One setting changed from the default: `finalmask.quicParams.maxIncomingStreams = 2^60`.
Xray's Hysteria server allows 1024 concurrent streams per QUIC connection by
default, the sing-box, mihomo and Citrus Hysteria2 servers (sing-quic) allow
2^60. Xray's own client opens a stream without waiting for credit, so with
the default 99.9% of the short connections of the handshake phase failed
(smoke run: 1023 conn/s and ~100 000 resets in 2 s) and 5000 idle tunnels
were impossible. With the setting all phases ran without errors.

TLS key exchange (probe on every TCP+TLS run): X25519MLKEM768 on every server
for `reality`, `xhttp`, `trojan`, `anytls` (see `tables.md`). Hysteria2 and
TUIC (QUIC) are not probed; SS2022 has no TLS.

Hysteria2 and TUIC carry every proxied connection as a stream of one QUIC
connection, and the AnyTLS client reuses idle sessions: for them, "new
connections" (handshake phase, TTFB) are new streams, not new handshakes, and
an idle tunnel is an idle stream.

## Headline

Medians of 3 repetitions; the min–max of every cell is in `headline.md`.
**Bold** = the winner's range does not overlap anyone else's; "≈" = the best
median's range overlaps the others listed (a tie within the noise). The last
column compares Citrus with the best of the other three (positive = Citrus
better). Spreads are 1–5% for most cells; QUIC (hy2, tuic) and the
1-stream numbers spread up to 10–20%.

### Throughput, 32 streams, MB/s (10^6 bytes/s, higher is better)

Download:

| protocol | Xray | sing-box | mihomo | Citrus | winner | Citrus vs best other |
|---|---|---|---|---|---|---|
| reality | 2173 (2132–2188) | 2653 (2621–2667) | 2837 (2706–2839) | 2800 (2715–2859) | ≈ mihomo, Citrus | -1% vs mihomo |
| reality-tlsin | 1331 (928–1397) | 5339 (5191–5544) | 9797 (9188–10516) | 9032 (7973–9057) | **mihomo** | -8% vs mihomo |
| xhttp | 925 (894–941) | n/a | 1185 (1166–1186) | 1189 (1158–1193) | ≈ Citrus, mihomo | +0% vs mihomo |
| trojan | 2095 (2068–2176) | 2856 (2704–2892) | 2794 (2730–2807) | 2807 (2794–2832) | ≈ sing-box, mihomo, Citrus | -2% vs sing-box |
| ss2022 | 1985 (1925–2012) | 4234 (4016–4283) | 3906 (3880–3933) | 3870 (3855–3903) | **sing-box** | -9% vs sing-box |
| hy2 | 586 (564–609) | 645 (617–672) | 639 (561–642) | 623 (583–638) | ≈ sing-box, mihomo, Citrus | -3% vs sing-box |
| tuic | n/a | 455 (414–455) | 450 (425–529) | 426 (419–449) | ≈ sing-box, mihomo, Citrus | -6% vs sing-box |
| anytls | n/a | 2504 (2497–2513) | 2157 (2117–2264) | 2214 (2214–2251) | **sing-box** | -12% vs sing-box |

Upload:

| protocol | Xray | sing-box | mihomo | Citrus | winner | Citrus vs best other |
|---|---|---|---|---|---|---|
| reality | 1871 (1863–1880) | 1818 (1815–1854) | 1841 (1822–1870) | 2843 (2817–2906) | **Citrus** | +52% vs Xray |
| reality-tlsin | 2433 (2323–2673) | 2360 (2344–2416) | 5601 (5075–7475) | 2377 (2250–2518) | not comparable (client-side Vision switch) | – |
| xhttp | 1187 (1169–1245) | n/a | 1461 (1459–1578) | 1531 (1513–1681) | ≈ Citrus, mihomo | +5% vs mihomo |
| trojan | 3412 (3174–3500) | 1849 (1842–1882) | 1826 (1815–1857) | 2880 (2854–2899) | **Xray** | -16% vs Xray |
| ss2022 | 3355 (3160–3421) | 1840 (1816–1850) | 1808 (1800–1834) | 2770 (2754–2780) | **Xray** | -17% vs Xray |
| hy2 | 580 (558–591) | 515 (481–520) | 613 (552–615) | 575 (533–584) | ≈ mihomo, Xray, Citrus | -6% vs mihomo |
| tuic | n/a | 488 (462–502) | 583 (553–586) | 575 (554–578) | ≈ mihomo, Citrus | -1% vs mihomo |
| anytls | n/a | 3223 (3203–3274) | 2923 (2844–3024) | 2792 (2677–2884) | **sing-box** | -13% vs sing-box |

`reality-tlsin` upload is **not comparable**: the Xray client decides it, not
the server. Xray's Vision writer switches an upload to direct copy only when
one of its socket reads holds whole TLS records; the bench writes the 1-byte
inner command record and the bulk data back to back, so depending on how the
client's reads split them a stream is padded to the end (~400 MB/s on any
server, Xray's included: 417/416/411 MB/s in `../2026-10-16`) or goes
direct (~3000 MB/s). Citrus's three single-stream values here are 385, 392,
2209 MB/s. No server ranking and no Citrus/mihomo-vs-Xray conclusion is drawn
from those cells (also the CPU-per-GB upload cells of `reality-tlsin`).

### Server CPU per GB, CPU s/GB (lower is better)

At 500 Mbit/s, one stream (same work for every server):

| protocol | download: Xray / sing-box / mihomo / Citrus | winner | upload: Xray / sing-box / mihomo / Citrus | winner |
|---|---|---|---|---|
| reality | 1.76 / 1.70 / 1.57 / 1.51 | ≈ Citrus, sing-box, mihomo | 1.99 / 2.02 / 1.97 / 1.99 | ≈ mihomo, Xray, sing-box, Citrus |
| reality-tlsin | 1.05 / 1.26 / 1.07 / 1.10 | ≈ Xray, mihomo, Citrus | 1.20 / 1.13 / 1.16 / 1.63 | not comparable (client-side Vision switch) |
| xhttp | 5.49 / n/a / 4.66 / 4.81 | ≈ mihomo, Citrus | 5.31 / n/a / 4.37 / 3.54 | **Citrus** |
| trojan | 2.27 / 1.54 / 1.51 / 1.50 | ≈ Citrus, sing-box, mihomo | 2.08 / 1.96 / 1.98 / 1.99 | ≈ sing-box, mihomo, Citrus |
| ss2022 | 2.23 / 1.39 / 1.37 / 1.40 | **mihomo** | 2.29 / 2.03 / 2.01 / 2.11 | ≈ mihomo, Xray, sing-box |
| hy2 | 5.63 / 4.83 / 4.55 / 4.63 | ≈ mihomo, sing-box, Citrus | 5.88 / 5.90 / 5.62 / 6.31 | ≈ mihomo, Xray, sing-box, Citrus |
| tuic | n/a / 4.76 / 4.52 / 4.70 | ≈ mihomo, sing-box, Citrus | n/a / 3.90 / 4.15 / 4.10 | ≈ sing-box, mihomo, Citrus |
| anytls | n/a / 1.72 / 1.77 / 1.75 | ≈ sing-box, mihomo, Citrus | n/a / 2.22 / 2.32 / 2.10 | ≈ Citrus, sing-box |

Bulk, 32 streams (unpaced):

| protocol | download: Xray / sing-box / mihomo / Citrus | winner | upload: Xray / sing-box / mihomo / Citrus | winner |
|---|---|---|---|---|
| reality | 0.88 / 0.72 / 0.68 / 0.67 | ≈ Citrus, mihomo | 1.02 / 1.05 / 1.04 / 0.66 | **Citrus** |
| reality-tlsin | 1.37 / 0.36 / 0.19 / 0.21 | **mihomo** | 0.77 / 0.80 / 0.33 / 0.82 | not comparable (client-side Vision switch) |
| xhttp | 2.15 / n/a / 1.63 / 1.59 | **Citrus** | 1.65 / n/a / 1.34 / 1.24 | ≈ Citrus, mihomo |
| trojan | 0.90 / 0.67 / 0.68 / 0.67 | ≈ sing-box, mihomo, Citrus | 0.55 / 1.04 / 1.04 / 0.66 | **Xray** |
| ss2022 | 0.96 / 0.45 / 0.49 / 0.49 | **sing-box** | 0.55 / 1.06 / 1.05 / 0.69 | **Xray** |
| hy2 | 2.33 / 2.09 / 2.04 / 2.10 | ≈ mihomo, Xray, sing-box, Citrus | 2.94 / 2.91 / 2.82 / 3.00 | ≈ mihomo, Xray, sing-box, Citrus |
| tuic | n/a / 2.16 / 2.23 / 2.18 | ≈ sing-box, mihomo, Citrus | n/a / 2.90 / 2.81 / 2.87 | ≈ mihomo, sing-box, Citrus |
| anytls | n/a / 0.75 / 0.87 / 0.85 | **sing-box** | n/a / 0.59 / 0.64 / 0.71 | **sing-box** |

### New connections (128 concurrent clients, request/answer, the sink closes)

| protocol | conn/s: Xray / sing-box / mihomo / Citrus | winner | server CPU ms per conn: Xray / sing-box / mihomo / Citrus | winner |
|---|---|---|---|---|
| reality | 3578 / 3115 / 2980 / 3363 | ≈ Xray, sing-box, Citrus | 0.536 / 0.605 / 0.645 / 0.564 | ≈ Xray, sing-box, Citrus |
| reality-x25519 | – / 3785 / 3752 / 3851 | ≈ Citrus, sing-box, mihomo | – / 0.500 / 0.519 / 0.497 | ≈ Citrus, sing-box, mihomo |
| xhttp | 9147 / n/a / 10366 / 10496 | ≈ Citrus, mihomo | 0.217 / n/a / 0.190 / 0.189 | ≈ Citrus, mihomo |
| trojan | 4371 / 5030 / 5263 / 5209 | ≈ mihomo, Citrus | 0.451 / 0.380 / 0.366 / 0.369 | ≈ mihomo, Citrus |
| ss2022 | 8435 / 9595 / 9477 / 9513 | ≈ sing-box, mihomo, Citrus | 0.233 / 0.201 / 0.200 / 0.201 | ≈ mihomo, sing-box, Citrus |
| hy2 | 14651 / 18607 / 17117 / 16322 | ≈ sing-box, mihomo | 0.130 / 0.100 / 0.113 / 0.116 | ≈ sing-box, Citrus |
| tuic | n/a / 20701 / 18585 / 18771 | **sing-box** | n/a / 0.088 / 0.100 / 0.096 | **sing-box** |
| anytls | n/a / 14763 / 12491 / 11713 | **sing-box** | n/a / 0.133 / 0.157 / 0.163 | **sing-box** |

### Idle tunnels: RSS per tunnel, KiB (lower is better)

| protocol | @5000: Xray / sing-box / mihomo / Citrus | winner | @1000: Xray / sing-box / mihomo / Citrus | winner |
|---|---|---|---|---|
| reality | 68.1 / 73.2 / 74.3 / 55.1 | **Citrus** | 52.8 / 70.8 / 71.0 / 48.8 | ≈ Citrus, Xray |
| xhttp | 62.5 / n/a / 56.2 / 53.4 | **Citrus** | 50.2 / n/a / 50.4 / 44.4 | **Citrus** |
| trojan | 84.9 / 38.0 / 63.1 / 51.6 | **sing-box** | 59.9 / 36.1 / 51.7 / 45.7 | **sing-box** |
| ss2022 | 60.2 / 90.1 / 54.5 / 48.8 | **Citrus** | 58.2 / 95.2 / 52.6 / 51.7 | ≈ Citrus, mihomo |
| hy2 | 41.3 / 23.7 / 28.6 / 26.0 | **sing-box** | 32.3 / 19.3 / 22.2 / 17.2 | ≈ Citrus, sing-box |
| tuic | n/a / 20.8 / 24.1 / – | **sing-box** | n/a / 17.2 / 18.6 / 13.4 | **Citrus** |
| anytls | n/a / 69.3 / 75.5 / 66.3 | **Citrus** | n/a / 67.2 / 65.0 / 66.5 | ≈ mihomo, sing-box, Citrus |

TUIC on Citrus: no value at 5000. Citrus's TUIC server allows 2048
concurrent bidirectional streams per QUIC connection (`listener/tuic/server.go`,
`ServerMaxIncomingStreams`), and the sing-box client does not wait for stream
credit: past 2048 it refuses new tunnels ("too many open streams", 2952
errors of 5000 in every repetition). The code comment assumes clients wait
for MAX_STREAMS; the sing-box client does not. A single sing-box TUIC client
with more than 2048 simultaneous TCP connections gets errors from Citrus and
not from mihomo or sing-box. At 1000 tunnels Citrus uses the least.

### Latency under load (8-stream unpaced download on the same server)

| protocol | echo RTT p50, ms: Xray / sing-box / mihomo / Citrus | winner | new-conn TTFB p50, ms: Xray / sing-box / mihomo / Citrus | winner |
|---|---|---|---|---|
| reality | 76.83 / 84.65 / 80.85 / 80.09 | **Xray** | 321.36 / 362.62 / 305.84 / 284.09 | **Citrus** |
| xhttp | 4.99 / n/a / 1.44 / 1.42 | ≈ Citrus, mihomo | 8.07 / n/a / 2.77 / 3.04 | ≈ mihomo, Citrus |
| trojan | 71.75 / 76.07 / 79.44 / 80.45 | **Xray** | 182.21 / 169.20 / 156.54 / 153.26 | **Citrus** |
| ss2022 | 80.08 / 45.85 / 71.34 / 69.33 | **sing-box** | 165.56 / 70.37 / 106.04 / 100.96 | **sing-box** |
| hy2 | 1.03 / 1.08 / 1.03 / 1.19 | ≈ Xray, sing-box, mihomo, Citrus | 1.62 / 1.74 / 1.91 / 1.80 | ≈ Xray, mihomo, Citrus |
| tuic | n/a / 1.84 / 2.66 / 2.46 | ≈ sing-box, mihomo, Citrus | n/a / 3.49 / 4.03 / 3.02 | ≈ Citrus, sing-box, mihomo |
| anytls | n/a / 88.43 / 90.81 / 91.01 | ≈ sing-box, mihomo, Citrus | n/a / 150.75 / 133.25 / 129.54 | ≈ Citrus, mihomo |

On the TCP protocols this RTT is mostly queueing in socket buffers behind the
unpaced download (70–90 ms at 2–4 GB/s); it tracks how much a server buffers,
not its scheduling. sing-box is lower on SS2022 (45 vs 69–80 ms) while also
downloading the fastest there. QUIC protocols stay at 1–3 ms because the
bulk rate is 5× lower.

## Verdict

**Citrus vs mihomo** (Citrus = mihomo + our changes):

- Upload is where Citrus is now clearly ahead (PR #119): 32 streams REALITY
  +54%, Trojan +58%, SS2022 +53%, single stream REALITY +49%, SS2022 +132%,
  TUIC +22%, AnyTLS +29%, with 34–37% less CPU per GB on REALITY/Trojan/SS2022
  bulk upload. XHTTP upload at 500 Mbit/s costs 19% less CPU.
- Download, CPU per GB at a fixed rate, new connections per second and CPU per
  connection: equal within the noise on every protocol but REALITY, where
  Citrus opens 13% more connections per second at 13% less CPU each (ranges
  apart). The 5–9% gap in new connections of `../2026-10-16` is gone
  (PR #118).
- Memory per idle tunnel: lower on REALITY (−26%), XHTTP (−5%), Trojan (−18%),
  SS2022 (−10%), Hysteria2 (−9%), AnyTLS (−12%); on TUIC lower at 1000
  tunnels but capped at 2048 streams per connection (above).
- Where Citrus trails mihomo: AnyTLS 32-stream upload (−4%, ranges overlap)
  at 11% more CPU per GB (0.71 vs 0.64), AnyTLS handshake TTFB p99 (28 vs
  23 ms; mihomo's range is wide, 21–38 ms), Hysteria2 handshake TTFB p99
  (16.7 vs 14.6 ms) and Hysteria2 upload CPU at 500 Mbit/s (6.31 vs 5.62
  CPU s/GB, ranges overlap). Single-stream AnyTLS download is equal (848 vs
  893, overlapping).

**Citrus vs Xray:**

- Download: Citrus is faster on every TCP protocol at 32 streams (REALITY
  +29%, Trojan +34%, SS2022 +95%, XHTTP +29%) and cheaper per GB (SS2022 1.40
  vs 2.23 CPU s/GB at 500 Mbit/s, Trojan 1.50 vs 2.27, XHTTP 4.81 vs 5.49).
  On Hysteria2 Citrus is also ahead on download (+6% at 32 streams, +39% on one
  stream, 18% less CPU per GB).
- Upload: Xray still leads on Trojan and SS2022 at 32 streams by 16–17%
  (3412 vs 2880, 3355 vs 2770 MB/s) and spends 21–25% less CPU per GB there;
  on one stream Citrus is equal (Trojan) or ahead (SS2022 +39%). On REALITY
  Citrus leads upload by +52%. XHTTP: Xray leads single-stream upload (+9%),
  Citrus leads 32 streams (+29%) and CPU per GB.
- New connections: equal on REALITY (Xray −6% median, ranges overlap);
  Citrus is faster on Trojan (+19%), SS2022
  (+13%), XHTTP (+15%) and Hysteria2 (+11%), with lower TTFB p99 (Trojan 47 vs
  84 ms, Hysteria2 17 vs 33 ms).
- Memory: Citrus uses less per idle tunnel on every protocol Xray has
  (REALITY −19%, Trojan −39%, SS2022 −19%, Hysteria2 −37%, XHTTP −15%).

**Citrus vs sing-box:**

- sing-box leads on AnyTLS across the board (Citrus: 32-stream download
  −12%, upload −13%, new connections/s −21% at +23% CPU per connection,
  TTFB p99 28 vs 20 ms, 13–20% more CPU per GB on bulk; single-stream
  upload is the exception, Citrus +10%), on TUIC new connections (Citrus
  −9%, +9% CPU per connection), Hysteria2 new connections (Citrus −12%;
  sing-box's range overlaps mihomo's), SS2022 download (Citrus −9% at 32
  streams, −13% single stream) and memory on Trojan (Citrus 52 vs 38 KiB
  per tunnel) and Hysteria2 (26 vs 24 KiB).
- Citrus leads on upload (REALITY +56%, Trojan +56%, SS2022 +52% at 32
  streams, TUIC +18%, AnyTLS single stream +10%), REALITY memory (55 vs 73
  KiB) and SS2022 memory (49 vs 90 KiB), REALITY handshake TTFB p99 and
  REALITY Vision direct-copy download (`reality-tlsin` 9032 vs 5339 MB/s).
- Equal: Trojan download and CPU, REALITY download, fixed-rate CPU per GB on
  every protocol but SS2022, TUIC and Hysteria2 throughput.

**Overall.** No core wins everywhere. On this host, among the four, Citrus
has the best or tied-best result on most TCP metrics (REALITY, Trojan,
SS2022, XHTTP): download on par with mihomo and sing-box and far ahead of
Xray, upload ahead of mihomo and sing-box by 50%+ (behind Xray by 16–17% on
Trojan/SS2022 bulk upload), new connections on par with mihomo (13% ahead
on REALITY), and the
lowest memory per tunnel on REALITY, XHTTP and SS2022. sing-box is the
reference on AnyTLS and TUIC (and its new-connection path is the cheapest
on the QUIC protocols); Xray remains the most CPU-efficient on Trojan/SS2022
bulk upload. On the QUIC protocols (Hysteria2, TUIC) sing-box, mihomo and
Citrus are within
the noise on throughput and CPU per GB (Xray trails on Hysteria2 download
and CPU); differences there are in new
streams and memory.

## Caveats

- One host, one bridge: no latency, no loss. Congestion control barely acts,
  so the QUIC numbers say little about lossy links. CPU per GB, CPU per
  connection and memory per tunnel carry over to real nodes better than MB/s.
- Docker Desktop on WSL2, hybrid CPU: the cpusets pin vCPUs, Hyper-V may move
  them between P- and E-cores. The rotation of the server order and the
  repetitions are there for that; read differences inside the min–max spread
  as noise.
- QUIC: one QUIC connection carries every tunnel, served by about one core on
  each end; the client container never exceeded 48% of its 14 vCPUs, but one
  client goroutine can still be the limit of a QUIC connection, so the hy2 /
  tuic MB/s are an upper bound set by the pair, not by the server alone. The
  client is the same for every server of a protocol.
- AnyTLS and TUIC use the sing-box client: it is the same binary family as one
  of the servers. This could favour sing-box's server on these two protocols
  (same implementation on both ends); Xray has neither protocol and the
  mihomo client would favour mihomo and Citrus.
- Latency under load on TCP is buffer queueing (see above).
- `reality-tlsin` uploads are decided by the client (see above).
- Defaults otherwise: log level `warning`/`warn`; Citrus keeps its per-user
  traffic accounting on; Citrus's GC ballast (server builds) is on; the only
  non-default server setting is Xray's Hysteria `maxIncomingStreams`.
- The server containers get `NET_ADMIN` (QUIC buffers above `rmem_max`), all
  four alike.

## Runs redone

The host was shared with other agents' containers (Go race tests, other
benchmarks). `run.sh` waited before each run until no other container ran
(`ALONE=1`, `waits.txt`), but some started during a run. A poller recorded
every foreign container every 2 s; runs that overlapped one were redone
(`ONLY=...`) and the originals moved to `disturbed/` (logs; the result JSON of
six of them was overwritten by the redo):

| run | overlapped by | redo |
|---|---|---|
| xray-reality-rep1, citrus-reality-rep1 | Go race-test containers | clean (`env-rerun1.txt`) |
| singbox-reality-x25519-rep1, citrus-xhttp-rep1, citrus-trojan-rep1, xray-ss2022-rep1 | Go race-test containers | clean (`env-rerun1.txt`) |
| singbox-ss2022-rep1 | race test, then another benchmark | 2nd redo clean (`env-rerun2.txt`) |
| citrus-reality-rep3, xray-reality-rep3 | another benchmark (its client's `pkill` also killed ours, see the harness fix) | 2nd redo was 30–55% slower on both servers with no container in sight (host load outside Docker); kept in `disturbed/slow/`, 3rd redo clean and in line with reps 1–2 (`env-rerun3.txt`) |

The 2nd and 3rd redos ran a build of `cf20ab88` (Citrus code identical to
`cc48b139`, only the harness changed) on subnet 10.89.0.0/24.

Follow-ups:

- `reality-tlsin` upload: add a short pause between the inner command write
  and the bulk writes, or record per stream whether Vision went direct.
- Citrus TUIC stream limit: 2048 refuses tunnels of clients that do not wait
  for stream credit (sing-box). Raise it, or make it configurable.
- AnyTLS: Citrus and mihomo trail sing-box by 13–22% on throughput and new
  sessions; worth a profile.
