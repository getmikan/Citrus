---
title: Audit closed, cascades, events, unix sockets and DNSCrypt
description: The week in dev — the audit fixes, chain groups, the /events stream, listeners on a unix socket, DNSCrypt and tests with mihomo clients.
date: 2026-10-15
---

Everything below is merged into `dev` and not in a release yet. To try it, [build the core from source](/Citrus/en/start/getting-started/#build-from-source). The full list is in the [changelog](/Citrus/en/changelog/).

## The audit is closed

The static audit of the core has been worked through: its findings were fixed in a series of PRs from [#75](https://github.com/getmikan/Citrus/pull/75) to [#97](https://github.com/getmikan/Citrus/pull/97), each with a test that fails on the old code. What users will notice most:

- a controller on a network address needs a `secret`, and on loopback without a secret it refuses browser requests from other sites;
- the HTTP proxy authenticates every request, UDP through SOCKS5 is bound to its user and port, and a password change closes sessions;
- self-update checks the package against the release's `checksums.txt`;
- a public provider URL cannot redirect into a private network, and paths are checked with symlinks resolved;
- state a client creates before authentication is bounded in every protocol;
- GitHub Actions and images are pinned by digest.

Some of these need config changes: they are collected on the new [Migrating from mihomo](/Citrus/en/migration/) page. How to report a vulnerability and what has been done to harden the core is on the [Security](/Citrus/en/security/) page.

## Cascades ([#73](https://github.com/getmikan/Citrus/pull/73))

The new `type: chain` group builds a chain of proxies and groups: the first hop is the entry, the last one is the exit.

```yaml
proxy-groups:
  - name: exits
    type: url-test
    proxies: [exit-de, exit-nl]
    url: https://cp.cloudflare.com/generate_204
  - name: cascade
    type: chain
    proxies: [entry, exits]   # entry → best exit
    url: https://cp.cloudflare.com/generate_204
    interval: 300
```

When the chain fails, the health check finds the first broken hop and reports it in `/proxies`, `/metrics` and a `chain.health` event. More on the [Chains](/Citrus/en/start/chains/) page.

## The event stream ([#70](https://github.com/getmikan/Citrus/pull/70))

`GET /events` streams core events over WebSocket, SSE or NDJSON: authentication, limits that kick in, user changes, config reloads, provider updates, listener and chain state. A panel no longer has to poll `/traffic/users` and `/limits/users` to learn that a quota ran out. See [Events](/Citrus/en/start/events/).

## Unix sockets ([#68](https://github.com/getmikan/Citrus/pull/68))

TCP listeners (VLESS, Trojan, TrustTunnel, HTTP, SOCKS and more) can listen on a unix socket: `listen: unix:/run/citrus/vless.sock`. That makes it easy to put a node behind nginx or Caddy, with the real client address passed through `trusted-proxy-header` and `trusted-proxies: [loopback]`.

## DNSCrypt ([#63](https://github.com/getmikan/Citrus/pull/63))

DNSCrypt v2 servers are set as `sdns://` stamps in `nameserver`. Queries go through the same dialer as the other DNS clients, so `#proxy` and the rules apply and nothing leaks under TUN. No third-party DNSCrypt library was needed.

## mihomo clients ([#74](https://github.com/getmikan/Citrus/pull/74))

A new interop suite runs the official mihomo v1.19.31 and v1.19.32 releases as clients against a Citrus server, the way the apps of Mikan users work. All 31 cases pass: REALITY with post-quantum settings, XHTTP, WebSocket, gRPC, Trojan, Shadowsocks 2022, Hysteria2, TUIC v5, AnyTLS, TrustTunnel, Snell, Mieru, Sudoku, HTTP and SOCKS. No incompatibility was found. The table is on the [Compatibility](/Citrus/en/compatibility/) page.

## Also

- `PUT /rules` replaces the rules without a config reload ([#64](https://github.com/getmikan/Citrus/pull/64)).
- XHTTP over h2 uses half the CPU per gigabyte ([#53](https://github.com/getmikan/Citrus/pull/53)), and an idle connection takes 30 KB less memory ([#52](https://github.com/getmikan/Citrus/pull/52)).
- JSON logs for Loki and ELK: `log-format: json` ([#65](https://github.com/getmikan/Citrus/pull/65)).
- The getmikan/tls and getmikan/utls forks carry the TLS security fixes from Go 1.26 ([#58](https://github.com/getmikan/Citrus/pull/58)).

What comes next, the first release and moving the Mikan panel to Citrus, is on the [Roadmap](/Citrus/en/roadmap/).
