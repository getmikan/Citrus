# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability. Report it privately through
GitHub's private vulnerability reporting:
[Security > Report a vulnerability](https://github.com/getmikan/Citrus/security/advisories/new).
Only the maintainers see the report; the discussion and the fix happen in a
private advisory.

Please include:

- the Citrus version or commit and the platform;
- the affected component (a protocol, a listener, the controller, the updater, ...);
- a minimal config and the steps to reproduce;
- what an attacker can do and what access they need.

We acknowledge the report, fix it on a private branch, publish the fix and the
advisory, and credit the reporter if they wish.

Issues in the forks [getmikan/utls](https://github.com/getmikan/utls),
[getmikan/tls](https://github.com/getmikan/tls) and
[getmikan/http](https://github.com/getmikan/http) can be reported here as well.
If the problem also exists in mihomo, say so in the report.

## Supported versions

Fixes land on `dev`, then in `main` and in releases. There are no maintenance
branches for older versions: update to the latest build.

More on the hardening work: https://getmikan.github.io/Citrus/en/security/
