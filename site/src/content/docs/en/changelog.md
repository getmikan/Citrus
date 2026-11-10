---
title: Changelog
description: Every pull request merged into Citrus, by area, with links, and the versions of the utls, tls and http forks.
---

Everything merged into `dev` since the project started (177 pull requests), by area. Within an area the order is by PR number. Links go to the PRs in [getmikan/Citrus](https://github.com/getmikan/Citrus/pulls?q=is%3Apr+is%3Amerged), which describe what was wrong, what changed and how it was tested.

The first beta release, [`v1.0.0-beta.1`](https://github.com/getmikan/Citrus/releases/tag/v1.0.0-beta.1), is built from `dev` up to [#112](https://github.com/getmikan/Citrus/pull/112). The second, [`v1.0.0-beta.2`](https://github.com/getmikan/Citrus/releases/tag/v1.0.0-beta.2), is built from `dev` up to [#133](https://github.com/getmikan/Citrus/pull/133). The changes for the third beta since #149 are in the first section below.

What changes behaviour for existing configs is collected on [Migrating from mihomo](/Citrus/en/migration/).

## v1.0.0-beta.3 (not released yet)

What has been merged into `dev` since [#149](https://github.com/getmikan/Citrus/pull/149) and goes into the third beta. [#182](https://github.com/getmikan/Citrus/pull/182) is still open but goes into it too. #130 and #134–#148 were merged after the `v1.0.0-beta.2` tag and also go into the third beta; they are listed in the areas below.

### Desync outbound

- [#163](https://github.com/getmikan/Citrus/pull/163) The `type: desync` outbound: a direct connection whose first TLS ClientHello is transformed by the [desync](https://github.com/Nemu-x/desync) library (`tlsrec`, `split`, `split-delay`, and on Windows `fake` and a UDP burst). The global DIRECT is unchanged; rules and groups pick it like DIRECT, and fallback or url-test with a VPN node as backup switch over when desync does not get through. Relay fast paths cannot bypass the wrapper, the egress guard applies to it, and `/proxies` shows the `Desync` type and a `desync` object. See [Desync](/Citrus/en/start/desync/).
- [#172](https://github.com/getmikan/Citrus/pull/172) desync v0.1.0: `split-wait`, `disorder`, `oob`, `random`; `fake` gains `auto-ttl`, its own SNIs, randomization and an offset; `udp` gains a QUIC template and `quic-only`. Fake now also works on Linux/Android and together with split, the UDP burst on Windows, Linux and macOS. Each method is checked against what the OS supports, an unsupported one is a config error with the reason; `/proxies` shows the last fake TTL.
- [#180](https://github.com/getmikan/Citrus/pull/180) Android: `fake`, `disorder` and `split-wait: sent`, which the library checks on each connection (SELinux keeps apps from reading a socket's unsent bytes), are no longer refused when the config loads. desync is bumped to the `main` commit that becomes v0.2.1.

### Fallbacks and the fallback page

- [#153](https://github.com/getmikan/Citrus/pull/153) `fallback-page` for VLESS and Trojan on HTTP transports (WebSocket, gRPC, XHTTP): requests that are not the inbound's own get an HTML page at `/` instead of a bare 404.
- [#159](https://github.com/getmikan/Citrus/pull/159) `fallbacks` for VLESS and Trojan on plain TCP, as in Xray: a foreign stream after TLS goes to `dest` (a port, `host:port` or a unix socket, `xver` for PROXY protocol), chosen by SNI, ALPN and path. Port 443 can be shared with a site, and Xray configs with fallbacks carry over. See [Fallbacks](/Citrus/en/start/fallbacks/).

### XHTTP over HTTP/3

- [#160](https://github.com/getmikan/Citrus/pull/160) The VLESS inbound with `xhttp-config` takes `alpn`, like `tlsSettings.alpn` in Xray: `[h3]` is XHTTP over QUIC on UDP only, `h3` together with `h2`/`http/1.1` adds UDP on the same port as TCP. Every XHTTP mode works over h3, each stream has a header deadline; configs that cannot work (REALITY, a unix socket, `proxy-protocol` with h3 and others) are refused.

### Egress guard

- [#162](https://github.com/getmikan/Citrus/pull/162) `egress-guard` (on by default): users of server inbounds cannot reach private and local networks, the host's own addresses or cloud metadata through DIRECT. The resolved addresses are checked right before connect, so DNS rebinding and IP4P do not get past it; UDP datagrams to blocked addresses are dropped. `allow-ips` opens single addresses or ports, and each listener has its own `egress-guard`. Client inbounds are not checked. A server whose users went to the LAN or to the host's localhost needs `allow-ips` or `egress-guard.enable: false`. See [Server without root](/Citrus/en/start/server-profile/).

### Root certificates

- [#161](https://github.com/getmikan/Citrus/pull/161) The Mozilla bundle lives in the repository (`make ca-bundle` checks curl's SHA-256) instead of being copied from the runner at build time. `tls.ca-roots: both | bundle | system` (default `both`, as before) and `tls.ca-denylist` (on by default): chains through Russian Trusted Root/Sub CA and the Kazakh interception roots are refused. The certificate pool is built before the proxies, so `ca-roots` and `custom-certifactes` reach them on the first start and on reload; sudoku wss, XDrive and the H3 DoH probe verify through it too.

### Limits

- [#151](https://github.com/getmikan/Citrus/pull/151) Limits: `speed-group`, one speed shared by several users on any inbounds; a new speed without resetting the bucket; `SetLimits` for many limits at once and `SetOnLeave` for traffic by destination in an embedding application.
- [#152](https://github.com/getmikan/Citrus/pull/152) Limits docs: a `speed-group` in the default limit (`user: "*"`) puts every user of the inbound without a limit of their own on one shared speed.

### Server hardening

- [#155](https://github.com/getmikan/Citrus/pull/155) Fixes from a full scan of the server side: controller transport and authentication, exact DoH routing, peer identity for SSH, OpenVPN and Realm, SSRF through redirects, Ed25519-signed self-update manifests with key rotation, expiry and anti-rollback, SHA-256 pins for GEO, UI installation through `os.Root`, rule-provider budgets, NTP isolation, secrets redacted from argv and provider URLs.
- [#156](https://github.com/getmikan/Citrus/pull/156) The `geox-sha256` pin is optional: without it remote GeoIP/GeoSite/MMDB/ASN load again (after #155 the core with the default config did not load GeoSite), with it a database with another hash is refused. `geodata-allow-unsigned` is gone.

### Second core audit

- [#166](https://github.com/getmikan/Citrus/pull/166) `common/`: the handshake listener behind REALITY, ShadowTLS, JLS and restls no longer dies for good when sockets run out (EMFILE, ENOBUFS); temporary Accept errors are retried with back-off, and the same for the PROXY protocol listener; passwords are compared in constant time; an overflow in `ReadAllLimit` is fixed.
- [#167](https://github.com/getmikan/Citrus/pull/167) DNS: `LookupIP4P` no longer panics on some IPv4 addresses or rewrites Teredo addresses; DHCP errors are not cached for an hour; an upstream OPT record does not go to a client that did not ask for it; a race in fake-ip; an unauthenticated DNSCrypt reply is dropped.
- [#168](https://github.com/getmikan/Citrus/pull/168) `adapter/`: the XDrive `local` and `template` modes are refused for proxies from subscriptions (they allowed requests to localhost and the LAN and writes to any path on disk); ssh and openvpn without an identity policy in a subscription are skipped instead of failing it; WireGuard keeps its devices behind smux on reload.
- [#169](https://github.com/getmikan/Citrus/pull/169) `listener/`: a failed reload no longer leaves an inbound closed after the rollback; a failing constructor closes whatever it opened; every inbound's accept loop uses a shared back-off instead of spinning at 100% CPU; keep-alive and a constant-time token check in Hysteria2 Realm; SOCKS5 UDP takes the inbound's users into account.
- [#170](https://github.com/getmikan/Citrus/pull/170) TUN: `auto-redirect` without `auto-route` is a config error instead of a nil panic; the loop detector catches system/mixed stack loops after the sniffer replaced the address; DNS hijack relays are capped; a failed CAS no longer zeroes `routing-mark`; a stack whose Start failed is closed.
- [#171](https://github.com/getmikan/Citrus/pull/171) Transports: AnyTLS no longer leaks its receive budget on a local close (the session froze); ShadowQUIC does not hang on Close; MASQUE no longer leaks the request stream when CONNECT fails; kcptun `Close` closes its sessions; the TUIC stream counter does not go negative; a CPU budget for the Sudoku probe; OpenVPN no longer holds 64 KiB per queued datagram.
- [#176](https://github.com/getmikan/Citrus/pull/176) Mux.Cool: one stream's deadline no longer breaks the whole session, an empty session closes after 16 s as in Xray, a 30 s write watchdog; XHTTP drops upload packets with an already read seq; the VLESS Encryption 0-RTT ticket survives a read deadline and Close; ShadowTLS v3 relays a ClientHello without SNI to the handshake server.
- [#177](https://github.com/getmikan/Citrus/pull/177) Rules and tunnel: a broken MRS DomainSet no longer crashes the core, a provider parser panic becomes a load error; the destination host is lowercased and loses the root dot, so `DOMAIN,youtube.com` also matches `YouTube.COM.`; `match()` does not hold the config lock while resolving; a UDP session's process is looked up once.
- [#178](https://github.com/getmikan/Citrus/pull/178) Self-update: an atomic core replace with rollback, ARM32 and loong64 support, the right asset for 386 softfloat; MMDB updates without munmap under live lookups; the GEO updater survives a failure, the old UI stays until the new one is fully copied; the controller restarts its listener after a failed reload, `/storage` refuses a key it cannot store, restart and upgrade are refused with a config from stdin; a redirect target keeps its host name.

### Fixes and dependencies

- [#157](https://github.com/getmikan/Citrus/pull/157) Windows: TUN with `auto-route` notices Forwarding and WeakHostSend on the egress adapter (ICS and the mobile hotspot turn them on, and then the core's sockets go into its own TUN). The core only logs a warning and sends a `tun.forwarding` event to `/events`; it does not change the adapter.
- [#183](https://github.com/getmikan/Citrus/pull/183) The egress guard judges an IPv6 address without its zone (`address%x` got past it); ShadowTLS with `wildcard-sni` vets the SNI of an authenticated client too (it could reach localhost and private hosts on 443); with `egress-guard` on a listener a Trojan or Mieru UDP session no longer moves to another user; a warning in the log for a user with an empty password. `x/net`, brotli and `x/crypto` updated (govulncheck findings), and undici and zod on the site (Dependabot alerts).

### Sync with mihomo

- [#182](https://github.com/getmikan/Citrus/pull/182) (open) Sync with mihomo Alpha: Snell v6 (inbound and outbound), TUN `dns-mode` and an auto-route fix, a Shadowsocks password generator, mieru idle close, the rewritten Sudoku transport with the Citrus limits ported onto it. Fixes: SOCKS domain length overflow, bytes after the HTTP CONNECT response, ssh, easytier, tfo-go on Go 1.26.9+. Not taken: the multi-user Shadowsocks inbound with a `users` map (in Citrus `users` is the SS2022 list with stats and limits) and the VMess share-link changes. Changed after the review: the Snell v6 `mode: unsafe-raw` is rejected, because it never uses the PSK — no authentication and no encryption, so an inbound in it is an open proxy; on Linux without `auto-route` an empty `dns-mode` means `native`, so systemd-resolved keeps sending DNS into the tunnel as before. Note: TUN with `auto-route` and a prefix without a DNS address (for example, a single `/32` and no IPv6) now fails to start; it used to start without DNS.

### Tests, CI and docs

- [#149](https://github.com/getmikan/Citrus/pull/149) Changelog brought up to #130–#138, roadmap after the post-beta.2 work.
- [#150](https://github.com/getmikan/Citrus/pull/150) An independent Linux CI job for the complete inbound suite with the race detector, including concurrent subtests in one process. Logs are preserved as artifacts; protocol-isolated checks remain enabled.
- [#154](https://github.com/getmikan/Citrus/pull/154) The changelog PR count after #150 and #152.
- [#158](https://github.com/getmikan/Citrus/pull/158) Interop with sing-box v1.14.4 in CI: the sing-box client against the Citrus server (VLESS, REALITY, Trojan, SS2022, Hysteria2, TUIC v5, AnyTLS) and the Citrus client against the sing-box server. On the way the loop detector stopped refusing legitimate connections of proxy inbounds.
- [#164](https://github.com/getmikan/Citrus/pull/164) Bench: Xray pinned to v26.10.21 (the v26.10.17 release is gone), the memory baseline recomputed on the new runner image.
- [#165](https://github.com/getmikan/Citrus/pull/165) The DNSCrypt test picks random port pairs (reserved ranges on Windows).
- [#173](https://github.com/getmikan/Citrus/pull/173) The XHTTP test waits for `onClose` after a read deadline.
- [#174](https://github.com/getmikan/Citrus/pull/174) The TrustTunnel fallback tests set users before `Start`.
- [#175](https://github.com/getmikan/Citrus/pull/175) The inbound H3 tests tell reserved Windows ports from taken ones.
- [#179](https://github.com/getmikan/Citrus/pull/179) `TestInboundUserStats` reports a failed transfer right away instead of a counter mismatch.

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
