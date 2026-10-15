<h1 align="center">
  <img src="assets/avatars/citrus-lime.png" alt="Citrus" width="160">
  <br>Citrus
</h1>

<p align="center">The network core for Mikan.</p>

<p align="center">
  <a href="https://github.com/getmikan/Citrus/actions/workflows/test.yml"><img src="https://github.com/getmikan/Citrus/actions/workflows/test.yml/badge.svg?branch=main" alt="Tests"></a>
  <a href="https://github.com/getmikan/Citrus/blob/main/go.mod"><img src="https://img.shields.io/github/go-mod/go-version/getmikan/Citrus/main?style=flat-square" alt="Go version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-orange?style=flat-square" alt="GPL-3.0 license"></a>
</p>

Citrus is a cross-platform proxy core maintained by [Mikan](https://github.com/getmikan).
It combines local proxy listeners, encrypted DNS, TUN networking, and rule-based routing
in one YAML configuration.

## Features

- HTTP, HTTPS, SOCKS, mixed, redirect, and TPROXY listeners.
- VLESS, Shadowsocks, Trojan, Snell, TUIC, Hysteria2, and other outbound protocols.
- TUN networking with a configurable network stack.
- DNS over HTTPS, TLS, and QUIC, with fake IP and DNS routing rules.
- Routing by domain, IP range, geodata, process, and logical rule combinations.
- Remote proxy and rule providers, health checks, fallback, and load balancing.
- HTTP and WebSocket controller APIs for compatible clients and dashboards.

## Branches and builds

| Branch | Role | Automated build |
| --- | --- | --- |
| [`main`](https://github.com/getmikan/Citrus/tree/main) | Primary branch | `Prerelease-main` |
| [`dev`](https://github.com/getmikan/Citrus/tree/dev) | Integration branch, all PRs | — (tested, not packaged) |

Build artifacts are available through [GitHub Actions](https://github.com/getmikan/Citrus/actions)
and published builds through [Releases](https://github.com/getmikan/Citrus/releases).
Release files use the `citrus-<os>-<architecture>-<version>` naming scheme.

## Configuration

Start with the annotated [configuration reference](docs/config.yaml).
Citrus reads `config.yaml` from its configuration directory:

- Linux and macOS: `~/.config/citrus/`, or `$XDG_CONFIG_HOME/citrus/` when configured.
- Windows: `%USERPROFILE%/.config/citrus/`.
- Linux packages: `/etc/citrus/` when started by `citrus.service`.

Use `-d` to select a directory or `-f` to select a configuration file.
An existing configuration can be used by passing its directory explicitly.

```shell
citrus -d /path/to/config
citrus -t -f /path/to/config.yaml
citrus -v
```

The upstream [configuration documentation](https://wiki.metacubex.one/) describes
the shared configuration format and controller API.
Compatible dashboards include [MetaCubeXD](https://github.com/MetaCubeX/metacubexd).

## Build from source

The module needs Go 1.26 or newer. Windows and macOS releases are built with the patched
[MetaCubeX Go toolchain](https://github.com/MetaCubeX/go), which keeps Windows 7/8 and older
macOS working (not tested separately). Linux needs kernel 3.2 or newer. There are no separate
builds on old Go versions (`-go120` and the like).

```shell
git clone https://github.com/getmikan/Citrus.git
cd Citrus
go mod download
go build -tags with_gvisor -trimpath -o citrus .
./citrus -v
```

On Windows, use `-o citrus.exe` and run `./citrus.exe`.
The Go module path remains `github.com/metacubex/mihomo`. Internal package names and protobuf
namespaces follow upstream to make cherry-picks and pull request transfers easier.
The product, executable, and release assets are named Citrus / `citrus`.

```shell
go test ./...
go test -tags with_gvisor ./...
```

The separate `test/` module contains integration tests that require their external
services and Docker fixtures. CI disables optional external interoperability tests
with `SKIP_INTEROP_TEST=1`.

## Updates

Core updates download Citrus assets from this repository.
The `main` and `dev` channels follow their respective prerelease builds; `release`
uses the latest tagged release. Automatic channel selection follows the running
binary's version. The legacy `alpha` channel name selects `main` for client compatibility.

## Credits and license

Citrus is an independent fork of the [MetaCubeX](https://github.com/MetaCubeX) network core.
The original Git history and contributor authorship are preserved.

The project builds on work from [Dreamacro](https://github.com/Dreamacro/clash),
[SagerNet](https://github.com/SagerNet/sing-box),
[v2fly](https://github.com/v2fly/v2ray-core),
[WireGuard](https://github.com/WireGuard/wireguard-go), and the other dependencies
listed in [go.mod](go.mod).

Citrus is distributed under the [GNU GPL-3.0 license](LICENSE).
