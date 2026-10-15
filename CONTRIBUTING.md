# Contributing to Citrus

Citrus is the network core of [Mikan](https://github.com/getmikan), a fork of
[MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo).

## Branches

| Branch | What goes there |
| --- | --- |
| `dev` | All pull requests. Tested on every push, not packaged. |
| `main` | Only merges from `dev`, done by maintainers. Builds as `Prerelease-main` and releases. |

**Open every pull request against `dev`.** A PR against `main` will be asked to
change its base branch. Both branches are protected: no direct pushes, no force
pushes, and `main` needs an approving review.

## Pull requests

1. Branch from `dev`: `feat/...`, `fix/...`, `chore/...`, `ci/...`, `docs/...`.
2. Keep one change per PR. Say what was wrong, what changed and how you tested it.
3. Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
   `feat(xhttp): ...`, `fix(reality): ...`.
4. Add or update tests for the behaviour you change, and run them locally:

   ```sh
   SKIP_INTEROP_TEST=1 go test ./...
   go vet ./...
   gofmt -l <the files you changed>
   ```

5. CI must be green: Test (Linux and Windows), PR Build (cross-compile) and
   Security (gofmt on changed files, vet, `go mod tidy`, govulncheck,
   dependency review). The full release build runs on `main` and tags.

## Upstream

Citrus follows mihomo's `Alpha` branch. Upstream syncs come in as their own PRs
to `dev`, so keep unrelated reformatting of upstream files out of your change:
it turns every later sync into a conflict.

Keep the Go module path `github.com/metacubex/mihomo`. Downstream code imports
Citrus through a `replace` directive and depends on it.

## Protocols

Citrus has dropped legacy protocols (VMess, ShadowsocksR, Hysteria v1, TUIC v4,
Shadowsocks stream ciphers, v2ray-plugin). New protocol or transport work should
target VLESS, Trojan, Hysteria2, TUIC v5, AnyTLS, TrustTunnel and the other
protocols Mikan ships. Ask in an issue before starting larger work.

## Security issues

Do not open public issues for vulnerabilities. Report them privately through
[GitHub Security Advisories](https://github.com/getmikan/Citrus/security/advisories/new).

## License

By contributing you agree that your work is released under the
[GPL-3.0](LICENSE) license of this repository.
