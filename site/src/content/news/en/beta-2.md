---
title: Second beta — faster upload and download, lower latency under load
description: v1.0.0-beta.2 — a comparison with Xray, sing-box and mihomo on one host, faster download, latency under load, tunnel memory, TUIC, smux and quota fixes.
date: 2026-10-18
---

The second beta release, [`v1.0.0-beta.2`](https://github.com/getmikan/Citrus/releases/tag/v1.0.0-beta.2), is out. The full list of changes is in the [changelog](/Citrus/en/changelog/).

## Four servers compared ([#126](https://github.com/getmikan/Citrus/pull/126))

Citrus, Xray v26.10.17, sing-box v1.14.3 and mihomo v1.19.32 were measured as servers on one host, eight protocols, the same clients for all. The results:

- Citrus leads upload: REALITY with 32 streams is 52% faster than the best of the others, and single-stream upload on REALITY and SS2022 is 40–49% faster.
- Citrus uses the least memory per idle tunnel on most protocols.
- sing-box leads AnyTLS, TUIC new connections and SS2022 download.
- Xray leads Trojan and SS2022 upload with 32 streams.

These numbers were measured before the changes below. The method, the caveats and every table are in `test/bench/compare/results/2026-10-18-four-cores/RESULTS.md` in the repository.

## Merged after the comparison

- **Download** ([#124](https://github.com/getmikan/Citrus/pull/124)). 64 KiB reads, and TLS records go to the socket together (in the getmikan/tls and getmikan/utls forks). With 32 streams, as the bench reports them: REALITY 2802 → 4235 MB/s, Trojan 2737 → 3936, SS2022 3895 → 4392.
- **Latency under load** ([#131](https://github.com/getmikan/Citrus/pull/131)). An echo next to eight downloads: 55–63 → 20 ms. For comparison, Xray is at about 77 ms and sing-box on SS2022 at about 47.
- **Idle tunnel memory** ([#129](https://github.com/getmikan/Citrus/pull/129)). Trojan −36% (37.7 KiB, below sing-box's 43.6), AnyTLS −18%, REALITY −12%.
- **QUIC** ([#125](https://github.com/getmikan/Citrus/pull/125)). The gap to sing-box on new streams went from 10–12% down to 4–6%.

Upload write batching ([#119](https://github.com/getmikan/Citrus/pull/119)) and fewer allocations per new connection ([#118](https://github.com/getmikan/Citrus/pull/118)) were in `dev` before the comparison; its numbers already include them.

## Fixes

- TUIC: a `CONNECT` with a 255-byte domain no longer crashes the server before authentication ([#125](https://github.com/getmikan/Citrus/pull/125)).
- smux is replaced with the [getmikan/smux](https://github.com/getmikan/smux) fork: after an error a caller's buffer is no longer sent ([#123](https://github.com/getmikan/Citrus/pull/123)).
- Limits: a race when closing a user over quota no longer touches the user's new connections ([#116](https://github.com/getmikan/Citrus/pull/116)).

## CI

- A `-race` job for the packages without races ([#121](https://github.com/getmikan/Citrus/pull/121)).
- A nightly performance check against mihomo ([#127](https://github.com/getmikan/Citrus/pull/127)).

## Known issues

The TUIC server accepts at most 2048 streams per QUIC connection. A client that opens more without waiting for stream credit (the sing-box client does this) gets errors on the extra ones.

## Next

The AnyTLS rework ([#130](https://github.com/getmikan/Citrus/pull/130)) is planned for the next beta. The rest is on the [Roadmap](/Citrus/en/roadmap/).
