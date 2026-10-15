---
title: Post-quantum REALITY, faster XHTTP through CDNs, and a protocol cleanup
description: Merged into dev — post-quantum REALITY on the client and server, faster packet-up through CDNs, legacy protocols removed, a rejected-auth hook and race fixes.
date: 2026-10-12
---

Everything below is merged into the `dev` branch but is not in a release or prerelease yet. `dev` is no longer packaged as `Prerelease-dev`, so for now the only way to try it is to [build the core from source](/Citrus/en/start/getting-started/#build-from-source) on the `dev` branch.

## Post-quantum REALITY ([#8](https://github.com/getmikan/Citrus/pull/8), [#10](https://github.com/getmikan/Citrus/pull/10))

Since Xray 26.9.8, a REALITY server silently drops any ClientHello without an X25519MLKEM768 key share placed before X25519, so earlier Citrus could not connect to current Xray servers.

**Client (`reality-opts`)**

- X25519MLKEM768 is on by default. `support-x25519mlkem768: false` sends the classical hello for old servers. Fingerprints without ML-KEM (ios, edge, randomized and others) get the key share added.
- `client-version`: the Xray version the client reports to the server. Defaults to `26.10.10`, instead of the hard-coded `1.8.2`, so servers with `minClientVer` accept it.
- `mldsa65-verify`: checks the ML-DSA-65 signature in the temporary certificate, like Xray's `mldsa65Verify` (`pqv` in share links).
- `client-fingerprint: firefox` and `safari` now send the real Firefox 148 and Safari 26.3 hellos from our [getmikan/utls](https://github.com/getmikan/utls) fork. Xray names such as `hellofirefox_148`, `hellosafari_26_3` and `hellochrome_131` are accepted too.

```yaml
proxies:
  - name: vless-reality-vision
    type: vless
    server: server
    port: 443
    uuid: uuid
    network: tcp
    tls: true
    flow: xtls-rprx-vision
    servername: www.microsoft.com
    client-fingerprint: chrome
    reality-opts:
      public-key: xxx
      short-id: xxx
      # support-x25519mlkem768: true  # default; false only for old servers
      # client-version: 26.10.10      # default
      # mldsa65-verify: xxx           # ML-DSA-65 public key (pqv)
```

**Server (`reality-config` on inbounds)**

- `mldsa65-seed`: signs the temporary certificate with ML-DSA-65, like Xray's `mldsa65Seed`. The `dest` certificate chain must be at least about 3.5 KB, or the signature does not fit and the handshake fails. Xray has the same limit.
- `require-x25519mlkem768`: only accept clients with X25519MLKEM768; the rest fall back to `dest`.
- `min-client-ver` and `max-client-ver`: the accepted range of client versions.

```yaml
listeners:
  - name: vless-in
    type: vless
    port: 443
    users:
      - username: 1
        uuid: uuid
        flow: xtls-rprx-vision
    reality-config:
      dest: test.com:443
      private-key: xxx   # citrus generate reality-keypair
      short-id:
        - 0123456789abcdef
      server-names:
        - test.com
      # max-time-difference: 60000     # milliseconds
      # mldsa65-seed: xxx              # xray mldsa65
      # require-x25519mlkem768: true
      # min-client-ver: 26.9.8
      # max-client-ver: 26.10.10
```

Live-tested against Xray 26.10.10 (VLESS + Vision + REALITY) in both directions, a Citrus client to an Xray server and an Xray client to a Citrus server, with and without ML-DSA-65. A wrong key is rejected.

**Behaviour change.** `max-time-difference` is now in milliseconds, like Xray's `maxTimeDiff`. It used to be read as microseconds, so a value copied from an Xray config allowed 1000 times less clock skew. If you tuned the value for the old unit, divide it by 1000.

Every key is described in the [config reference](https://github.com/getmikan/Citrus/blob/dev/docs/config.yaml).

## XHTTP through CDNs ([#9](https://github.com/getmikan/Citrus/pull/9))

- In `packet-up` mode the next POST no longer waits for the previous response, as in Xray. Through a CDN each POST used to cost a full client → CDN → origin round trip, so upload was bound by latency. In a live test against Xray 26.10.10 a packet-up request took 0.4 s instead of 5.4 s. Over HTTP/1.1 responses are still awaited.
- `x-padding-bytes: "0-0"` now means Xray's default padding (100–1000 bytes) instead of none.
- A `path` with a query, such as `/xh?ed=2048`, is sent as a path and a query, as in Xray, instead of an escaped `%3F` inside the path.

## Legacy protocols removed ([#7](https://github.com/getmikan/Citrus/pull/7))

ShadowsocksR, Hysteria v1, TUIC v4, Shadowsocks stream ciphers (rc4-md5, aes-ctr/cfb, chacha20 and others) and v2ray-plugin are gone. Shadowsocks accepts only `none`, AEAD and `2022-blake3-*`. VMess stays for now.

- In a proxy provider such a node is skipped with a warning, and the rest of the subscription loads.
- In the main config it is an error with a clear message, for example "TUIC v4 is no longer supported, use uuid/password (v5)".

## Rejected-auth journal ([#5](https://github.com/getmikan/Citrus/pull/5))

The `component/authevent` package reports failed logins on TrustTunnel, REALITY, AnyTLS, VLESS, Trojan, TUIC v5, Hysteria2 and Sudoku inbounds: protocol, addresses and reason, never credentials. It is the core side of a journal of rejected requests in the panel. Events go through a queue and never slow down the handshake.

## Data races in Vision and AnyTLS ([#11](https://github.com/getmikan/Citrus/pull/11))

Fixed the data races `go test -race` found in the XTLS Vision filter and reader and in the AnyTLS stream. After the first packets, the Vision hot path costs one atomic load.
