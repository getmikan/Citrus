---
title: Citrus is live
description: The Mikan network core is now a project of its own, a mihomo fork with its own releases. What is there and what is planned.
date: 2026-10-11
---

Citrus is the network core of [Mikan](https://miroshka000.github.io/mikan/), a fork of [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo). The core now lives in its own repository, [getmikan/Citrus](https://github.com/getmikan/Citrus), with the upstream history and authorship kept, and ships its own releases.

## How development works

- Two branches: `dev` and `main`. Every pull request goes to `dev`; `main` only gets merges from `dev`.
- Each branch builds its own prerelease: `Prerelease-dev` and `Prerelease-main`. Stable versions ship as tagged releases.
- Changes from mihomo come in as separate PRs to `dev`.

See [Contributing](/Citrus/en/project/contributing/) for details.

## What is planned

These are plans, not finished work:

- **Drop legacy protocols**, starting with VMess.
- **Xray interoperability**, including post-quantum REALITY: X25519MLKEM768 key exchange and ML-DSA-65 signatures.
- **xhttp fixes.**

We will post here as each step lands in a release.
