---
title: Changelog
description: Every pull request merged into Citrus, by area, with links, and the versions of the utls, tls and http forks.
---

Everything merged into `dev` since the project started (146 pull requests), by area. Within an area the order is by PR number. Links go to the PRs in [getmikan/Citrus](https://github.com/getmikan/Citrus/pulls?q=is%3Apr+is%3Amerged), which describe what was wrong, what changed and how it was tested.

The first beta release, [`v1.0.0-beta.1`](https://github.com/getmikan/Citrus/releases/tag/v1.0.0-beta.1), is built from `dev` up to [#112](https://github.com/getmikan/Citrus/pull/112). The second, `v1.0.0-beta.2`, is built from `dev` as described on this page.

What changes behaviour for existing configs is collected on [Migrating from mihomo](/Citrus/en/migration/).

## Infrastructure, CI and docs

- [#2](https://github.com/getmikan/Citrus/pull/2) `dev` synced with `main`.
- [#3](https://github.com/getmikan/Citrus/pull/3) Security checks in CI (gofmt, vet, `go mod tidy`, govulncheck, CodeQL, dependency review) and CONTRIBUTING.md.
- [#4](https://github.com/getmikan/Citrus/pull/4) The Citrus site on GitHub Pages, with news.
- [#12](https://github.com/getmikan/Citrus/pull/12) Slim CI for PRs (about 8 jobs); the full build only on `main` and tags.
- [#13](https://github.com/getmikan/Citrus/pull/13) News post on post-quantum REALITY, XHTTP and removed protocols.
- [#24](https://github.com/getmikan/Citrus/pull/24) Weekly sync from mihomo Alpha (the workflow; not yet enabled in the settings).
- [#25](https://github.com/getmikan/Citrus/pull/25) Interop suite against Xray-core (REALITY PQ, XHTTP, ECH) and its CI job.
- [#51](https://github.com/getmikan/Citrus/pull/51) Load and benchmark harness and a first baseline.
- [#74](https://github.com/getmikan/Citrus/pull/74) Interop suite: mihomo v1.19.31 and v1.19.32 clients against a Citrus server.
- [#98](https://github.com/getmikan/Citrus/pull/98) Site pages: roadmap, changelog, compatibility, migrating from mihomo and security; landing refresh.
- [#99](https://github.com/getmikan/Citrus/pull/99) CI: site- and docs-only PRs skip the Go checks; the site is built on site PRs.
- [#101](https://github.com/getmikan/Citrus/pull/101) Server comparison of Xray-core, mihomo and Citrus: throughput, CPU per GB, new connections.
- [#108](https://github.com/getmikan/Citrus/pull/108) Changelog brought up to the v1.0.0-beta.1 release.
- [#110](https://github.com/getmikan/Citrus/pull/110) Go 1.26: `x/net`, `x/crypto`, `x/text` and `x/sys` updated (HTTP/2 and other vulnerabilities fixed), separate `-go120…-go125` builds dropped; Windows 7/8 and older macOS are covered by the patched MetaCubeX toolchain, Linux needs kernel 3.2+.
- [#112](https://github.com/getmikan/Citrus/pull/112) Changelog: #108, #110 and #111.
- [#114](https://github.com/getmikan/Citrus/pull/114) CI: pinned Go toolchain for tests, the PR build and the bench.
- [#120](https://github.com/getmikan/Citrus/pull/120) LF for `*.sh` and Dockerfile; triage of `-race` reports in `listener/inbound`.
- [#121](https://github.com/getmikan/Citrus/pull/121) CI: a `-race` job for the 30 race-clean packages.
- [#126](https://github.com/getmikan/Citrus/pull/126) Four-server comparison: Xray, sing-box, mihomo and Citrus, eight protocols.
- [#127](https://github.com/getmikan/Citrus/pull/127) Bench: deterministic REALITY upload with TLS inside the tunnel; a nightly performance check against mihomo in CI.
- [#144](https://github.com/getmikan/Citrus/pull/144) Optional non-root server profiles: dedicated systemd account with read-only config and bounded capabilities, and a Docker image using UID 65532. CI runs the real systemd unit and a zero-capability Docker relay test.
- [#132](https://github.com/getmikan/Citrus/pull/132) Changelog brought up to the second beta, v1.0.0-beta.2.
- [#134](https://github.com/getmikan/Citrus/pull/134) News post on the second beta, the roadmap after it.
- [#135](https://github.com/getmikan/Citrus/pull/135) Test and site dependencies: the Docker client in tests moved to `moby/moby`, `postcss-selector-parser` bumped — the Dependabot alerts are closed.
- [#150](https://github.com/getmikan/Citrus/pull/150) Added an independent Linux CI job for the complete inbound suite with the race detector, including concurrent subtests in one process. Logs are preserved as artifacts; protocol-isolated checks remain enabled.

## Removed legacy

- [#7](https://github.com/getmikan/Citrus/pull/7) Removed SSR, Hysteria v1, TUIC v4, Shadowsocks stream ciphers and v2ray-plugin.
- [#38](https://github.com/getmikan/Citrus/pull/38) The shared TLS/WS/H2 transport moved out of `transport/vmess` into `transport/v2ray`.
- [#39](https://github.com/getmikan/Citrus/pull/39) Removed VMess, mKCP, mekya and TLSMirror.

## Xray and post-quantum

- [#8](https://github.com/getmikan/Citrus/pull/8) Post-quantum REALITY client for Xray 26.9.8+: ML-KEM by default, ML-DSA-65, `client-version`.
- [#9](https://github.com/getmikan/Citrus/pull/9) XHTTP: faster packet-up through CDNs, Xray-compatible padding, path query and xmux defaults.
- [#10](https://github.com/getmikan/Citrus/pull/10) Post-quantum REALITY server and Firefox 148 / Safari 26.3 fingerprints (getmikan/utls).
- [#19](https://github.com/getmikan/Citrus/pull/19) ECH: Xray `echServerKeys` in `ech-key`, `ech-opts.query-server` and Xray `ech=` link forms.
- [#20](https://github.com/getmikan/Citrus/pull/20) XHTTP server accepts packet-up with any method and data placement like Xray; `server-max-header-bytes`.
- [#21](https://github.com/getmikan/Citrus/pull/21) HTTP/2 inbounds send the same first SETTINGS frame as Caddy (getmikan/http).
- [#34](https://github.com/getmikan/Citrus/pull/34) XHTTP: Xray's default XMUX when `reuse-settings` is empty, reuse manager fixes.
- [#139](https://github.com/getmikan/Citrus/pull/139) XDrive for VLESS clients and servers: local, Google Drive and template API storage, VLESS Encryption, Mux.Cool and XUDP; Xray interoperability and race checks in CI.

## VPN service features

- [#1](https://github.com/getmikan/Citrus/pull/1) TrustTunnel: a `fallback` site for requests without valid credentials (from Kinkan).
- [#5](https://github.com/getmikan/Citrus/pull/5) Events for rejected authentication on inbound listeners (`authevent`, from Kinkan).
- [#36](https://github.com/getmikan/Citrus/pull/36) TrustTunnel: cover-site visits aren't reported as authentication events.
- [#41](https://github.com/getmikan/Citrus/pull/41) Multi-user Shadowsocks 2022 inbound (EIH) with per-user identity.
- [#42](https://github.com/getmikan/Citrus/pull/42) Per-user traffic and online IPs in the core, REST and Go API.
- [#43](https://github.com/getmikan/Citrus/pull/43) Inbound users changed at runtime: REST `/inbounds/{name}/users`, in-place reload.
- [#44](https://github.com/getmikan/Citrus/pull/44) Per-user limits in the core: speed, connections, IPs, quota, expiry.
- [#47](https://github.com/getmikan/Citrus/pull/47) Prometheus `/metrics` and `/healthz`, `/readyz` probes.
- [#63](https://github.com/getmikan/Citrus/pull/63) DNSCrypt v2 resolver for `sdns://` stamps.
- [#64](https://github.com/getmikan/Citrus/pull/64) `PUT /rules`: replace rules at runtime.
- [#68](https://github.com/getmikan/Citrus/pull/68) TCP stream listeners on a unix socket.
- [#70](https://github.com/getmikan/Citrus/pull/70) `GET /events`, a push stream of core events.
- [#71](https://github.com/getmikan/Citrus/pull/71) TrustTunnel: per-proxy HTTP/2 session timers.
- [#73](https://github.com/getmikan/Citrus/pull/73) `type: chain` groups for cascades, with a health check that names the failed hop.
- [#136](https://github.com/getmikan/Citrus/pull/136) PROXY protocol v1 and v2 on the TCP inbounds (`proxy-protocol`, `proxy-protocol-trusted`): the client address from the header of a front end such as an SNI router on 443.
- [#146](https://github.com/getmikan/Citrus/pull/146) Default User-Agent `clash.meta/<version> citrus/<version>`: panels still recognise mihomo by the start of the string, Citrus stands out by the `citrus/` token.
- [#147](https://github.com/getmikan/Citrus/pull/147) Added `core: "citrus"` to controller `GET /version`, preserving the existing `meta` and `version` fields for panels.
- [#151](https://github.com/getmikan/Citrus/pull/151) Limits: `speed-group`, one speed shared by several users on any inbounds; a new speed without resetting the bucket; `SetLimits` for many limits at once and `SetOnLeave` for traffic by destination in an embedding application.

## Performance

- [#30](https://github.com/getmikan/Citrus/pull/30) Snell v4: buffered reader, about 90× fewer read syscalls.
- [#52](https://github.com/getmikan/Citrus/pull/52) Idle connections don't pin a 32 KB buffer: −30 KB heap per connection.
- [#53](https://github.com/getmikan/Citrus/pull/53) XHTTP: half the CPU per GB on h2 downloads (getmikan/http).
- [#118](https://github.com/getmikan/Citrus/pull/118) New connections: fewer GC cycles and allocations per connection (GC ballast in server builds only).
- [#119](https://github.com/getmikan/Citrus/pull/119) Upload: batched writes with read-ahead, up to +50% on REALITY, Trojan and SS2022, −34% CPU per GB.
- [#124](https://github.com/getmikan/Citrus/pull/124) Download: 64 KiB reads, TLS records sent to the socket together (getmikan/tls, getmikan/utls): +40–50% with 32 streams, −25–30% latency under load.
- [#125](https://github.com/getmikan/Citrus/pull/125) Hysteria2 and TUIC: less work per stream, the read buffer only when needed, no first-bytes wait goroutine for DIRECT.
- [#129](https://github.com/getmikan/Citrus/pull/129) Idle tunnel memory: Trojan −36%, AnyTLS −18%, REALITY −12% (getmikan/tls: read buffer sized by what is moving, `WaitRead`).
- [#131](https://github.com/getmikan/Citrus/pull/131) Latency under load: the relay loop yields after 256 KiB and 1 ms; an echo next to eight downloads 55–63 → 20 ms.
- [#130](https://github.com/getmikan/Citrus/pull/130) AnyTLS: received frames queued on their stream, outgoing frames built in place; with 32 streams download is twice as fast, upload +23%, CPU per GB nearly halved; the client race is gone.

## Hardening

- [#14](https://github.com/getmikan/Citrus/pull/14) Controller: owner-only unix socket and named pipe, secret on every listener, `/debug` behind auth.
- [#15](https://github.com/getmikan/Citrus/pull/15) TLS 1.2 minimum, verified Hysteria2 masquerade, owner-only files, redacted DoH credentials.
- [#16](https://github.com/getmikan/Citrus/pull/16) Bounds on remote downloads, archive extraction, DoH bodies and binary rule/geodata parsers.
- [#17](https://github.com/getmikan/Citrus/pull/17) ShadowTLS: no fallback to private or local addresses for unauthenticated clients.
- [#18](https://github.com/getmikan/Citrus/pull/18) SOCKS5 UDP only for authenticated UDP ASSOCIATE and allowed sources.
- [#22](https://github.com/getmikan/Citrus/pull/22) `tcp-concurrent`: bounded fan-out, losing dials cancelled.
- [#23](https://github.com/getmikan/Citrus/pull/23) DIRECT dials the address the IP rules checked.
- [#26](https://github.com/getmikan/Citrus/pull/26) Bounded pre-auth state: VLESS 0-RTT tickets, XHTTP sessions without data.
- [#37](https://github.com/getmikan/Citrus/pull/37) Handshake deadline before authentication: VLESS, Trojan, AnyTLS, HTTP transports.
- [#55](https://github.com/getmikan/Citrus/pull/55) getmikan/utls v1.8.8-citrus.2: TLS library bug fixes.
- [#56](https://github.com/getmikan/Citrus/pull/56) Code review batch: mmdb, share-link cert verify, obfs/Sudoku limits, listener deadlines, regexp timeouts.
- [#58](https://github.com/getmikan/Citrus/pull/58) Go 1.26 TLS security fixes (ECH CVE-2026-97031, KeyUpdate) via getmikan/tls and getmikan/utls.

## Audit fixes

- [#75](https://github.com/getmikan/Citrus/pull/75) CI: actions and images pinned to digests, least-privilege tokens.
- [#76](https://github.com/getmikan/Citrus/pull/76) Bounded peer-declared frame lengths (gun, MASQUE h2, TrustTunnel UDP, VLESS addons).
- [#77](https://github.com/getmikan/Citrus/pull/77) Updater verifies core packages against `checksums.txt` and ignores names inside packages.
- [#78](https://github.com/getmikan/Citrus/pull/78) Symlink-aware safe paths, atomic resource writes, no redirects into private networks.
- [#79](https://github.com/getmikan/Citrus/pull/79) Controller: secret on network addresses, browser guard, reload of controller settings.
- [#80](https://github.com/getmikan/Citrus/pull/80) A reload without `force` applies the inbound access policy.
- [#81](https://github.com/getmikan/Citrus/pull/81) Sudoku: bounded replay cache, mux streams and http-mask uploads.
- [#82](https://github.com/getmikan/Citrus/pull/82) Credentials and core files kept out of reach of the API.
- [#83](https://github.com/getmikan/Citrus/pull/83) Providers: bounded `override-expr`, provider size and logic nesting; atomic rule-set swap.
- [#84](https://github.com/getmikan/Citrus/pull/84) Snell and Shadowsocks: handshake deadline before authentication.
- [#85](https://github.com/getmikan/Citrus/pull/85) HTTP proxy authenticates every request on a keep-alive connection.
- [#86](https://github.com/getmikan/Citrus/pull/86) Global authentication sessions revoked on reload; empty usernames refused.
- [#87](https://github.com/getmikan/Citrus/pull/87) SSH host-key warning and opt-out; OpenVPN server identity checks.
- [#88](https://github.com/getmikan/Citrus/pull/88) SOCKS5: UDP associations bound to their user and source port.
- [#89](https://github.com/getmikan/Citrus/pull/89) Bounded NTP clock steps; DNS cache keyed by client subnet.
- [#90](https://github.com/getmikan/Citrus/pull/90) AnyTLS and Trojan: capped streams per mux session.
- [#91](https://github.com/getmikan/Citrus/pull/91) QUIC: bounded stream limits for TUIC, ShadowQUIC and TrustTunnel; TUIC pre-auth budget.
- [#92](https://github.com/getmikan/Citrus/pull/92) QUIC: bounded TUIC fragment reassembly and ShadowQUIC unbound association state.
- [#93](https://github.com/getmikan/Citrus/pull/93) UDP sessions keyed by inbound and user, not only by source.
- [#94](https://github.com/getmikan/Citrus/pull/94) Keys and credentials kept out of logs; `age decrypt` writes its file with mode 0600.
- [#95](https://github.com/getmikan/Citrus/pull/95) Snell: the user verified by ShadowTLS/JLS wins over the client ID.
- [#96](https://github.com/getmikan/Citrus/pull/96) Hysteria2 Realm: IP header only from `trusted-proxies`; session tokens kept out of logs.
- [#97](https://github.com/getmikan/Citrus/pull/97) XHTTP: sessions stay in the pre-auth limits until VLESS authenticates them.
- [#102](https://github.com/getmikan/Citrus/pull/102) Snell: the client ID no longer becomes the user; without ShadowTLS or JLS the inbound has no user.
- [#103](https://github.com/getmikan/Citrus/pull/103) DNS listener: in-flight queries capped, each with a deadline.
- [#104](https://github.com/getmikan/Citrus/pull/104) Hysteria2 Realm: one events stream per session; `Close` ends the active connections.
- [#105](https://github.com/getmikan/Citrus/pull/105) Providers: the health-check URL is logged without its password and query values.
- [#107](https://github.com/getmikan/Citrus/pull/107) CI: the remaining actions and fpm pinned; Go toolchains checked against SHA-256.
- [#111](https://github.com/getmikan/Citrus/pull/111) AnyTLS: the peer version from session settings is parsed with a bounds check, so `-1` no longer turns on v2 behaviour (found by CodeQL).
- [#113](https://github.com/getmikan/Citrus/pull/113) AnyTLS: bounded padding scheme and number parsing; `compress` and `dhcp` bumped.
- [#140](https://github.com/getmikan/Citrus/pull/140) Bounded VLESS replay history and aggregate Sudoku HTTP-mask upload buffers; 64 KiB Sudoku write chunks; invalid ML-DSA seeds are omitted from errors.
- [#141](https://github.com/getmikan/Citrus/pull/141) Updated uTLS and ResTLS forks in all three modules: REALITY deadlines until classification, exact fallback limiter threshold, no AuthKey/short ID in logs, cached X25519 keys/buffers, JLS verification callbacks and atomic ResTLS counters.
- [#142](https://github.com/getmikan/Citrus/pull/142) Bounded pending REALITY/ShadowTLS/JLS/ResTLS handshakes, ShadowTLS records, Sudoku fallback and KCPTun sessions/streams; server QUIC 0-RTT for TUIC/TrustTunnel is opt-in. Added regression and protocol-isolated inbound race tests; documented compatibility limitations without claiming Sudoku key-auth fixed.
- [#143](https://github.com/getmikan/Citrus/pull/143) Controller WebSockets use scoped single-use tickets (30 seconds, bounded storage); reusable URL secrets require an explicit compatibility option. Added migration instructions and hub race coverage.
- [#145](https://github.com/getmikan/Citrus/pull/145) Updated controller/events guides for one-time WebSocket tickets and documented package/image updates for the non-root server profile.
- [#148](https://github.com/getmikan/Citrus/pull/148) Updated ResTLS in all three modules: fixed a generic QUIC/TLS resumption debug-call panic; the fork now runs its complete TLS/ResTLS regression suite on Go 1.20/1.24/1.26, Windows and under the race detector.

## Ported from mihomo and the community

- [#27](https://github.com/getmikan/Citrus/pull/27) WireGuard: one device per key across reloads, devices of removed proxies closed.
- [#28](https://github.com/getmikan/Citrus/pull/28) Don't retry dials that failed on resource exhaustion.
- [#29](https://github.com/getmikan/Citrus/pull/29) Configurable `tcp-connect-timeout`.
- [#31](https://github.com/getmikan/Citrus/pull/31) DNS: `serve-expired` controls (defaults keep the current behaviour).
- [#32](https://github.com/getmikan/Citrus/pull/32) `trusted-proxy-header` for VLESS/Trojan, only from `trusted-proxies`.
- [#33](https://github.com/getmikan/Citrus/pull/33) BitTorrent sniffer (TCP, uTP, DHT, tracker) and the `PROTOCOL` rule.
- [#60](https://github.com/getmikan/Citrus/pull/60) Hosts: bounded domain mapping chains, followed by the core resolver.
- [#61](https://github.com/getmikan/Citrus/pull/61) url-test keeps the current node across provider updates.
- [#62](https://github.com/getmikan/Citrus/pull/62) Small ports: TUIC `Close`, `disable-mtu-discovery`, memory limit, sniffed domain in logs.
- [#65](https://github.com/getmikan/Citrus/pull/65) Small ports 2: JSON logs, `sniffer.skip-threshold`, fake-IP for escaped names, OpenVPN `tls-version-min`.
- [#66](https://github.com/getmikan/Citrus/pull/66) Tailscale: `dialer-proxy` works, and no UDP goes around it.
- [#117](https://github.com/getmikan/Citrus/pull/117) Sync with mihomo as of 17 October 2026.

## Bug and test fixes

- [#11](https://github.com/getmikan/Citrus/pull/11) Data races in Vision and AnyTLS.
- [#35](https://github.com/getmikan/Citrus/pull/35) Interop tests wait for Citrus to be ready before sending traffic.
- [#40](https://github.com/getmikan/Citrus/pull/40) TrustTunnel tests: flaky same-port TCP+UDP binds on Windows.
- [#45](https://github.com/getmikan/Citrus/pull/45) Flaky `TestBindRace`.
- [#46](https://github.com/getmikan/Citrus/pull/46) Stats: count relayed bytes whose write reports an error (h2mux undercount).
- [#48](https://github.com/getmikan/Citrus/pull/48) Flaky `TestInboundRuntimeUsersConcurrent` (loopback detector, TIME_WAIT).
- [#49](https://github.com/getmikan/Citrus/pull/49) Loopback detector matches DIRECT loops by the whole connection, not the source port.
- [#50](https://github.com/getmikan/Citrus/pull/50) Data races in the AnyTLS client session.
- [#54](https://github.com/getmikan/Citrus/pull/54) TrustTunnel client: bounded connections, dead HTTP/2 sessions closed.
- [#57](https://github.com/getmikan/Citrus/pull/57) Warning about the Windows UDP stack corruption in Go 1.26.0 and 1.26.1.
- [#59](https://github.com/getmikan/Citrus/pull/59) Flaky `TestTrackerSpeedLimit`.
- [#67](https://github.com/getmikan/Citrus/pull/67) SOCKS tests: Windows UDP port flake.
- [#69](https://github.com/getmikan/Citrus/pull/69) TrustTunnel server drops sessions of clients that vanished.
- [#72](https://github.com/getmikan/Citrus/pull/72) XHTTP: a passed deadline no longer tears down an idle conn; early user expiry; test races.
- [#100](https://github.com/getmikan/Citrus/pull/100) Flaky Trojan mux cap, TUIC pre-auth budget and TrustTunnel upload tests.
- [#106](https://github.com/getmikan/Citrus/pull/106) VLESS link redaction test skips unrelated log lines.
- [#115](https://github.com/getmikan/Citrus/pull/115) Flaky tests: AnyTLS interop with mihomo and the stalled TrustTunnel upload.
- [#116](https://github.com/getmikan/Citrus/pull/116) Limits: a late close of a user over its quota spares its new connections.
- [#122](https://github.com/getmikan/Citrus/pull/122) SOCKS UDP user test takes a free TCP port (Windows).
- [#123](https://github.com/getmikan/Citrus/pull/123) smux replaced by the getmikan/smux fork: the caller's buffer is no longer read after `Write` returns (its bytes could go out on another connection).
- [#125](https://github.com/getmikan/Citrus/pull/125) TUIC: a `CONNECT` to a 255-byte domain no longer crashes the server before authentication.
- [#137](https://github.com/getmikan/Citrus/pull/137) PROXY protocol: a v1 line shorter than the signature is rejected at once, without reading client data.
- [#138](https://github.com/getmikan/Citrus/pull/138) The SOCKS UDP user test takes a port free for both TCP and UDP (Windows).

## Forks

Citrus replaces five mihomo libraries with its own forks through `replace` in `go.mod`. Module paths stay the same; changes go through PRs and CI on `dev`, and releases are published separately.

### [getmikan/utls](https://github.com/getmikan/utls)

- `v1.8.9-0.20261020173537-32502cba39f4`: REALITY/JLS fixes from [fork PR 3](https://github.com/getmikan/utls/pull/3), pinned in [#141](https://github.com/getmikan/Citrus/pull/141); a `dev` commit, not a release tag.

- `v1.8.8-citrus.1`: the server side of post-quantum REALITY (ML-DSA-65 signature, X25519MLKEM768 requirement), Firefox 148 and Safari 26.3 fingerprints ([#10](https://github.com/getmikan/Citrus/pull/10)).
- `v1.8.8-citrus.2`: bug fixes from a code review: session resumption, ECH, server minimum version, compressed certificates, HKDF ([#55](https://github.com/getmikan/Citrus/pull/55)).
- `v1.8.8-citrus.3`: security fixes from Go 1.26: ECH outer extension validation (CVE-2026-97031) and KeyUpdate ([#58](https://github.com/getmikan/Citrus/pull/58)).
- After `v1.8.8-citrus.3`, `dev` commits: the records of one write go to the socket together ([#124](https://github.com/getmikan/Citrus/pull/124)).

### [getmikan/tls](https://github.com/getmikan/tls)

- `v0.1.8-citrus.1`: the same ECH fix (CVE-2026-97031) for TLS inbounds ([#58](https://github.com/getmikan/Citrus/pull/58)).
- After `v0.1.8-citrus.1`, `dev` commits: the records of one write go to the socket together ([#124](https://github.com/getmikan/Citrus/pull/124)), a read buffer sized by what is moving and `Conn.WaitRead` ([#129](https://github.com/getmikan/Citrus/pull/129)).

### [getmikan/http](https://github.com/getmikan/http)

- `v0.1.8-citrus.1`: HTTP/2's first SETTINGS frame as Caddy sends it ([#21](https://github.com/getmikan/Citrus/pull/21)).
- `v0.1.8-citrus.2`: a 64 KiB HTTP/2 write buffer and batched WINDOW_UPDATE ([#53](https://github.com/getmikan/Citrus/pull/53)).

### [getmikan/smux](https://github.com/getmikan/smux)

- A `dev` commit: `Write` does not return while the send loop may still read the caller's buffer; an abandoned frame is not sent ([#123](https://github.com/getmikan/Citrus/pull/123)).

### [getmikan/restls-client-go](https://github.com/getmikan/restls-client-go)

- `v0.1.10-0.20261020174520-8a87bfbeac8c`: atomic full-duplex counters and fallback classification notification from [fork PR 1](https://github.com/getmikan/restls-client-go/pull/1), pinned in [#141](https://github.com/getmikan/Citrus/pull/141). Fork CI covers the ResTLS protocol; existing failures in the generic TLS suite are not claimed fixed.
- `v0.1.10-0.20261020200739-f74a25fc969b`: generic QUIC/TLS resumption panic fix and restored full TLS/ResTLS tests from [fork PR 2](https://github.com/getmikan/restls-client-go/pull/2), pinned in [#148](https://github.com/getmikan/Citrus/pull/148). The earlier generic-suite failures are now addressed; no tests are skipped to obtain a pass.
