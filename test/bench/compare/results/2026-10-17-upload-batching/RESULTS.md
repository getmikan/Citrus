# Upload write batching, 2026-10-17: Citrus before / after

Follow-up 2 of [`../2026-10-16/RESULTS.md`](../2026-10-16/RESULTS.md): upload
(client → server → target) under load cost Citrus about twice Xray's CPU per GB
on Trojan and Shadowsocks 2022.

Same harness and host as 2026-10-16 (`env.txt`, `test/bench/compare/run.sh`),
`PHASES=bulk,fixed`, 3 repetitions (xhttp rerun: 4), server order rotated. To
compare the two builds in the same run, the image carried the base build
(`dev` at `c2dc03ad`) in the slot of mihomo and the changed build in the slot
of Citrus; the configs of the two slots are identical. In the tables the
columns are renamed accordingly.

## Cause

CPU profile of the 32-stream Trojan upload on the base (`../2026-10-16/pprof/citrus-trojan-up32-cpu.pb.gz`):
`write(2)` to the target 65% of the server's CPU, `read(2)` 17%, AES-GCM 11%,
memmove 2%. A TLS connection returns one record (≤ 16 KiB) per read, a
Shadowsocks connection one chunk, and the relay wrote each with its own
`write(2)`. Neither source can tell whether more decrypted data is waiting,
so a single loop cannot batch without waiting.

## Change

`common/net/relay_batch.go`: while the copy is in a burst (the full-buffer
mode of the adaptive copy) and the destination is a socket, a reader goroutine
keeps reading and decrypting the source, at most 8 buffers ahead, and the copy
writes everything read meanwhile with one `writev(2)`. It never waits for more
data; when the burst ends (two short reads) the reader hands the source back
and exits, so an idle connection keeps waiting on the 2 KiB buffer without a
goroutine. Download (socket source: splice or read waiter) and Vision before
and after its direct copy are not on this path.

After (`pprof/citrus-trojan-up32-cpu.pb.gz`): `writev`/`write` 41% of the
server's CPU (from 65%), more of the remaining time in AES-GCM (16%) and
`read(2)` (27%), i.e. in moving more data.

## Results

Medians of 3 runs, min–max in the `tables-*.md` files. MB/s = 10^6 bytes/s;
CPU s/GB = server CPU seconds per 10^9 bytes.

| | Xray | Citrus base | Citrus batched | change |
|---|---|---|---|---|
| Trojan ul 32 streams, MB/s | 3449 | 1792 | 2683 | +50% |
| Trojan ul 32 streams, CPU s/GB | 0.54 | 1.06 | 0.70 | −34% |
| Trojan ul 1 stream, MB/s | 1139 | 798 | 1145 | +43% |
| SS2022 ul 32 streams, MB/s | 3417 | 1801 | 2814 | +56% |
| SS2022 ul 32 streams, CPU s/GB | 0.55 | 1.07 | 0.68 | −36% |
| SS2022 ul 1 stream, MB/s | 1253 | 714 | 1438 | +101% |
| REALITY ul 32 streams, MB/s | – | 1788 | 2758 | +54% |
| REALITY ul 32 streams, CPU s/GB | – | 1.06 | 0.69 | −35% |
| REALITY ul 1 stream, MB/s | – | 799 | 1178 | +47% |
| xhttp ul 32 streams, MB/s (rerun, 4 runs) | – | 1620 | 1632 | inside the spread |
| xhttp ul 32 streams, CPU s/GB (rerun) | – | 1.19 | 1.20 | inside the spread |

Unchanged (inside the spread): download on every protocol (1 and 32
streams, MB/s and CPU s/GB), and CPU per GB at a paced 500 Mbit/s in both
directions: Trojan upload 1.93 → 2.16 in the first run and 1.99 in the
read-ahead run (ranges 1.91–2.13, 2.01–2.16, 1.87–2.10), SS2022 2.00 → 2.03,
REALITY 2.05 → 2.03, xhttp 3.36 → 3.27. The first xhttp run
(`tables-reality-xhttp.md`) was noisy in both directions, including the
download that this change does not touch; the rerun with 4 repetitions
(`tables-xhttp-rerun.md`) shows no difference.

Read-ahead depth (`tables-readahead-4-vs-8.md`, 4 vs 8 buffers): 8 is a
little cheaper on 32 streams (Trojan 0.66 vs 0.70 CPU s/GB, SS2022 0.67 vs
0.72, ranges disjoint) and faster (2867 vs 2700, 2841 vs 2643 MB/s); kept at 8
(at most 8 × 32 KiB pool buffers per uploading connection while its target is
slower than its client, none while idle).

Xray is still cheaper on Trojan/SS2022 upload under load (0.54 vs 0.70 CPU
s/GB); we did not profile Xray to explain the rest.
