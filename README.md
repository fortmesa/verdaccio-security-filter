# `verdaccio-security-filter`

A supply-chain-hardening plugin for [Verdaccio](https://verdaccio.org): blocks
package versions that look like a supply-chain risk before a client can install
them, and (optionally) rejects a matching publish outright.

**Type**: Verdaccio `filter_metadata` plugin, and optionally also a
`middlewares` (Express) plugin -- see
[Publish-time gate](docs/configuration.md#publish-time-gate). **Config key**
(the literal, scoped package name -- Verdaccio never prefix-mangles a scoped
plugin's config key): `filters."@fortmesa/verdaccio-security-filter"` (always),
plus `middlewares."@fortmesa/verdaccio-security-filter"` (only if a publish-time
gate, or the OSV retroactive-alert check, is enabled).

## What it does

Runs on package metadata every time it's read via Verdaccio's `getPackage()`
(`npm view`, `npm install` resolution, etc.), before it's returned to a client,
and strips out (or, for some rules, replaces) versions that look like a
supply-chain risk. This applies to metadata for _any_ package the registry can
serve, not only ones proxied through an upstream uplink -- Verdaccio's storage
layer runs configured filters on purely-local package reads too, so this also
applies to internally-published packages' metadata, not just externally-sourced
ones.

Per version, in this order (an earlier rule matching always wins over a later
one -- see
[Manual block/allow lists](docs/configuration.md#manual-blockallow-lists-and-date-threshold)
for why this order):

1. **Allow-list** -- an operator-declared exception. Bypasses every rule below,
   including the synced malicious-package blocklist.
2. **Synced malicious-package blocklist (OSV)** -- a version matching a
   known-malicious-package advisory synced from
   [OSV](https://osv.dev)/[`ossf/malicious-packages`](https://github.com/ossf/malicious-packages)
   is blocked. See
   [Malicious-package blocklist (OSV)](docs/configuration.md#malicious-package-blocklist-osv).
3. **Manual `block:` list** -- an operator-declared package, scope, or version
   range.
4. **Too new / after a date threshold** -- any version published less than
   `packageAge.minDays` ago, or on/after `packageAge.thresholdDate`, is blocked.
   This gives the community time to catch and report a malicious or compromised
   release before it becomes installable through this registry.
5. **Newly-introduced install scripts** -- a version is blocked if it adds a
   `preinstall`/`install`/`postinstall` script that no earlier version of the
   package had, and that change happened within the last
   `packageAge.scriptCheckDays` days. The intent is to catch a previously
   script-free, trusted package suddenly gaining code-execution-on-install
   behavior (a common supply-chain compromise pattern), while leaving packages
   that have _always_ shipped install scripts (e.g. native addons) alone
   regardless of age.

A publish-time gate (see
[Publish-time gate](docs/configuration.md#publish-time-gate)) can additionally
**reject** a matching publish outright rather than just hiding it, and every OSV
sync proactively cross-references its newly-fetched data against packages
already cached locally (see
[Malicious-package blocklist (OSV)](docs/configuration.md#malicious-package-blocklist-osv)).
Both fire a single, static, configurable
[webhook](docs/configuration.md#webhooks) for immediate alerting.

## Installation

```bash
npm install @fortmesa/verdaccio-security-filter
```

Needs Node 22.12.0 or later and Verdaccio 6; the tests run against Verdaccio
6.7.4 and 6.10.7. Verdaccio resolves a plugin by package name against whatever
`plugins:` path you've configured -- see Verdaccio's own docs on
[plugin resolution](https://verdaccio.org/docs/plugin-develop) if you're
installing into a custom global location rather than a project's `node_modules`.

## Quick config

```yaml
filters:
  '@fortmesa/verdaccio-security-filter':
    packageAge:
      minDays: 2
      scriptCheckDays: 30
    allow:
      - '@your-trusted-scope/*'
    block:
      - '@known-bad-scope/*'
    osv:
      enabled: false # see docs/configuration.md before enabling
    webhook:
      url: https://example.com/hooks/verdaccio-security # optional
      body: '{"pkg":"{{pkg}}","ver":"{{ver}}","reason":"{{reason}}"}'
```

See [`docs/configuration.md`](docs/configuration.md) for the full reference:
manual block/allow list syntax, the OSV malicious-package blocklist (data
source, sync mechanism, cost characteristics), MAL confidence filtering, CVE
(GHSA) blocking, pluggable storage backends (filesystem/Redis/DynamoDB), the
publish-time gate, webhooks, and logging conventions.

## Testing

```bash
yarn install
yarn test
```

`yarn test` runs eight hand-rolled `node:assert` smoke files (no test framework
or build step) covering the filter, the publish gate, the OSV sync, each storage
backend, the audit endpoints, webhooks and the tarball check. It then runs
`test/verdaccio.js`, which starts a real Verdaccio with the plugin loaded as
both filter and middleware, in front of a fake uplink. `VERDACCIO_BIN` points
that file at another Verdaccio build:

```bash
VERDACCIO_BIN=../fm-npmjs/node_modules/verdaccio/bin/verdaccio node test/verdaccio.js
```

`yarn test:cli` (`test/cli-real.js`) drives real npm 5 to 11 and yarn 1 to 4
clients against a real Verdaccio, and takes the same `VERDACCIO_BIN`. It
downloads those clients on its first run.

## Dependencies

`semver`, `body-parser`, `minimatch`, `tar`, `yauzl`, `ae-cvss-calculator` --
see [Dependencies](docs/configuration.md#dependencies) for what each is used
for. `@aws-sdk/client-dynamodb`, `@aws-sdk/lib-dynamodb`, and `ioredis` are
optional peer dependencies -- only install the one matching whichever OSV
storage backend you configure.

## License

MIT -- see [LICENSE](LICENSE).
