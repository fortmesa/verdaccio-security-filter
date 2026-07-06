# Configuration reference

See the [README](../README.md) for the plugin's overall precedence order and a
quick-start config. This page covers everything else in depth.

## Full config

```yaml
filters:
  '@fortmesa/verdaccio-security-filter':
    packageAge:
      minDays: 2 # default 2 -- block versions newer than this
      scriptCheckDays: 30 # default 30 -- "recently introduced" window for install scripts
      thresholdDate: null # optional -- bare date ("2026-01-01") or full ISO-8601 timestamp; see "Manual block/allow lists" below
    block: [] # optional manual block list -- see below
    allow: [] # optional manual allow list -- see below
    blockPublishWithNewScripts: false # see "Publish-time gate"
    blockPublishMatches: false # see "Publish-time gate"
    # Single, static webhook target fired for every loud security event --
    # see "Webhooks" below. Omit entirely to disable.
    webhook:
      url: https://example.com/hooks/verdaccio-security
      body: '{"pkg":"{{pkg}}","ver":"{{ver}}","event":"{{event}}","reason":"{{reason}}"}'
      content-type: application/json
    # Malicious-package blocklist sync -- see "Malicious-package blocklist (OSV)"
    osv:
      enabled: false
      pollSeconds: 900
      pollJitter: 90
      baseUrl: 'https://osv-vulnerabilities.storage.googleapis.com/npm/'
      requestTimeoutSeconds: 30
      blockStrategy: remove # 'remove' (default) | 'replace'
      # Storage backend -- see "Storage backends" below. Auto-selected from
      # whichever of redis/dynamo/filesystem is configured (priority in that
      # order) -- configure exactly one.
      dynamo:
        tableName: verdaccio-malicious-packages
        region: us-east-1
        keyPrefix: ''
      # filesystem:
      #   path: /verdaccio/osv-storage
      # redis:
      #   url: redis://localhost:6379
      #   keyPrefix: ""
      # MAL confidence filters -- see "MAL confidence filtering" below
      malware:
        minOrigin: 1
        sources: []
      # CVE (GHSA) blocking -- see "CVE (GHSA) blocking" below
      cve:
        severity: []
        cwe: []
        cvss3Min: null
        cvss4Min: null
```

There's no separate skip-list for the age check -- a package that needs to
bypass `packageAge.minDays`/`thresholdDate` goes in `allow:` instead (see
below), same as any other allow-listed package. Since `allow:` bypasses
_everything_, not just the age check, this is broader than an age-only skip list
would be: an allow-listed package is also exempt from the OSV blocklist, the
manual `block:` list, and the install-script check.

## How the install-script check actually works

Versions are sorted oldest-first by their publish timestamp. A first pass walks
that history to find the _first_ time an install script appears immediately
after a version that had none -- that gap, in wall-clock time from now, is
`scriptIntroductionAge`. If a package has _always_ had install scripts (no
earlier clean version), or the introduction happened longer ago than
`packageAge.scriptCheckDays`, `scriptIntroductionIsRecent` is `false` and the
install-script rule never fires for that package at all, no matter how many
versions come after. A second pass then applies both rules per-version and
collects everything to block.

## Manual block/allow lists and date threshold

Brings this plugin to feature parity with the official
[`@verdaccio/package-filter`](https://www.npmjs.com/package/@verdaccio/package-filter)
plugin's `block:`/`allow:`/date-threshold capabilities, using a similar rule
shape. Each entry is either a bare glob pattern string (matches every version of
whatever it matches), or a single-key `{pattern: {versions?, strategy?}}` object
when a rule needs to be scoped to a semver range or (for `block:`) a `replace`
strategy -- the same bare-string-or-single-key-object shape `osv.cve.cwe` below
already uses:

```yaml
filters:
  '@fortmesa/verdaccio-security-filter':
    packageAge:
      thresholdDate: '2026-01-01' # only serve versions published before this date
    block:
      - 'left-pad'
      - '@known-bad-scope/*'
      - event-stream:
          versions: '>=3.3.6 <=3.3.6' # semver range, via the existing `semver` dependency
          strategy: replace # 'remove' (default) | 'replace'
    allow:
      - '@your-trusted-scope/*'
      - colors:
          versions: '1.4.0'
```

**`thresholdDate` combines with `minDays` via "earlier cutoff wins"** --
whichever cutoff is chronologically earlier blocks more (it draws the line
further back in time), matching `@verdaccio/package-filter`'s documented
semantics. `minDays: 2` alone means "block anything from the last 2 days";
`thresholdDate: 2020-01-01` alone means "block everything since 2020-01-01" --
if both are set, the more restrictive (earlier) one is the one that actually
applies. `thresholdDate` accepts either a bare date (`"2026-01-01"`, interpreted
as UTC midnight) or a full ISO-8601 timestamp (`"2026-01-01T00:00:00Z"`).

**Pattern matching uses real `minimatch`** -- the same convention Verdaccio's
own `packages:` access-control config uses (via `@verdaccio/utils`'s
`getMatchedPackagesSpec`), not a narrower hand-rolled matcher, and the same
convention every plugin in this family (see `verdaccio-attestations`) matches
package names with: an exact string like `"left-pad"` matches only that package;
a trailing-`*` pattern like `"@known-bad-scope/*"` matches anything with that
prefix, but (as a real minimatch `*`) never crosses a `/` -- not that this
matters for a real npm package name, which is never more than one scope segment
deep, so `"@evil/*"` still does _not_ match a package literally named `@evil`,
since that's not a real installable package name anyway; `"**"` matches every
package. An optional `versions` field (only available via the single-key object
form) scopes a rule to a semver range. Multiple rules can match the same
version; for `block:`, `strategy: replace` only applies if _every_ matching rule
says `replace`, otherwise the safer `remove` wins.

**Allow overrides everything, including the OSV blocklist** -- this goes beyond
what `@verdaccio/package-filter` itself does (it has no external synced list to
override), but follows the same principle it establishes: "allow rules are
checked before block rules... take precedence over all blocking rules." A
version matching an `allow:` rule is never blocked by anything else in this
plugin, full stop.

**`strategy: replace`** substitutes the nearest older non-blocked version
(falling back to the nearest newer one, then to a hard removal if neither
exists) instead of removing the blocked version outright -- useful when a
blocked version is a transitive dependency and removing it would break installs.
The packument keeps the blocked version's key and `version` field, but its
`dist`/tarball/integrity are copied wholesale from the substitute, so what
actually gets installed for that version number is the substitute's real,
already-published content. This is scoped to the manual `block:` list (and, if
`osv.blockStrategy: replace`, the OSV blocklist -- see below); age/date blocks
always hard-remove, since they're inherently self-resolving over time and
removing is simpler.

## Malicious-package blocklist (OSV)

The official `@verdaccio/package-filter` plugin above only supports a small
hand-maintained list. Live per-package queries against `api.osv.dev` put a
network call in the request path. Client-side tools (Google's `osv-scanner`,
Aikido Safe Chain, Socket's Registry Firewall) protect a developer's install
command or a separate proxy, not the registry itself. This plugin's OSV
integration is built to close that gap: block known malicious npm packages at
the registry, kept continuously current, with zero per-request cost.

**Data source**: [OSV](https://osv.dev)'s public, unauthenticated npm bulk
export, which is
[OpenSSF's `ossf/malicious-packages`](https://github.com/ossf/malicious-packages)
data (IDs prefixed `MAL-`) ingested into OSV's cross-ecosystem feed alongside
ordinary CVE/GHSA advisories.

**Only ~100 bytes/package is ever kept** -- package name, affected version
range(s), advisory id(s), and a modified timestamp. The full OSV record
(summary, details, credits) is parsed transiently during sync and discarded
immediately after extraction; it's never written to the storage backend or held
in memory past that single step.

**Sync mechanism**:

- **Bootstrap** (first-ever run against an empty storage backend): downloads the
  full `npm/all.zip` once, extracts minimal fields per non-withdrawn `MAL-`
  record, and batch-writes them to the configured backend.
- **Steady-state** (every `osv.pollSeconds`, default 900s/15min, +/-
  `osv.pollJitter` jitter on every tick including the first): a conditional GET
  (`If-None-Match`/`If-Modified-Since`) against `npm/modified_id.csv`. **A
  `304 Not Modified` ends the cycle immediately -- zero parsing, zero backend
  calls.** Only on an actual change does it diff rows against the last-processed
  high-water-mark, fetch the individual `npm/<ID>.json` records that changed,
  extract their minimal fields, and upsert just those.
- **Withdrawal**: an advisory OSV later retracts is removed from the affected
  package's entry (or the whole entry, if it was the only contributing advisory)
  on the next cycle that observes the withdrawal.
- Multiple replicas sync independently -- no leader election. Every write is an
  idempotent put/batch-write, so redundant work between replicas is harmless,
  and this avoids needing any distributed coordination for what's a low-volume
  background job.

**Per-request cost: zero.** `filter_metadata()` and the publish gate check a
plain in-memory `Map` lookup plus a small `semver` comparison -- no network
call, no backend request, regardless of how many packages a single `npm install`
resolves. The storage backend is touched _only_ by the background sync job
described above, bounded by `(replica count) x (1 cycle / osv.pollSeconds)`,
never by registry traffic.

**Startup/warm-start cost** (once per process lifecycle -- start, restart,
scale-up): a full scan of the whole backend populates the in-memory list before
the first periodic tick, so a freshly-started process doesn't wait a full poll
cycle for OSV-based blocking to become active. Verdaccio's plugin loader does
not await construction, so a process may serve a few seconds of traffic before
this completes; the pre-existing age/script checks are unaffected during that
window. Once loaded, the in-memory `Map` runs roughly 100-150MB of heap over the
current ~215k-entry/~50-60MB raw dataset -- worth sizing your process's memory
limit against as the OSV dataset grows.

**Already-cached packages that get flagged later**: no separate cache purge or
invalidation is needed. `filter_metadata()` re-runs on every metadata read
against whatever the blocklist currently contains, and Verdaccio's
`getTarball()` re-runs the same filter chain before streaming an already-cached
tarball from local storage, 404ing if the requested file no longer appears in
the filtered metadata. So a version cached before being OSV-flagged is blocked,
metadata _and_ tarball, the moment the next sync cycle ingests the advisory --
bounded only by the poll interval. The one thing no registry-side control can do
anything about: a client that already finished `npm install` before the block
took effect already has the bytes, on that machine or baked into a build
artifact.

That passive filtering happens silently, though -- it only becomes visible the
next time some client happens to request that exact package again. On top of it,
every **incremental** sync cycle (not bootstrap -- see below) also proactively
cross-references each newly-applied delta against whatever this registry
actually has cached/stored locally, right as the delta is ingested. A match logs
the loud, `fatal`-level `!!! CACHED PACKAGE NOW FLAGGED !!!` line (see "Logging"
below) and fires the configured `webhook:` (see "Webhooks" below) immediately,
rather than waiting on a coincidental future read to surface it. This requires
the plugin to also be listed under `middlewares:` (with at least an empty block,
`{}`, if you don't otherwise need the publish-time gates) --
`register_middlewares()` is the only Verdaccio hook that ever receives a
`storage` reference, which this check needs to look up what's actually cached.
Deliberately **not** run during bootstrap: that's a one-time, whole-history load
of the entire OSV feed, and treating every one of its (potentially thousands of)
entries as "new" would flood a fresh pod's first boot with alerts for advisories
that predate this registry ever caching anything -- noise, not signal. An
incremental sync's delta is genuinely new data, which is what this feature means
to alert on.

**`osv.blockStrategy`** (`remove` default, or `replace`) is one global policy
for every OSV hit, not a per-entry setting like manual `block:` rules get -- the
feed is auto-generated, not admin-authored, so there's no sensible place to
attach a per-advisory override.

**Provisioning**: enabling this requires a storage backend (see below) -- for
DynamoDB, a table keyed on a single string partition key `pk`, and IAM
permissions for `Scan`/`GetItem`/`PutItem`/`DeleteItem`/`BatchWriteItem` on it.
`osv.enabled` and `blockPublishMatches` both default to `false`; nothing in this
section does anything until both the infrastructure exists and the config is
turned on deliberately.

## Extraction schema versioning

`modified_id.csv`'s watermark only tracks whether OSV's _data_ changed -- never
whether this plugin's own interpretation of it did. A change to the extraction
logic itself can mean already-stored data is stale/incomplete in a way no amount
of waiting for OSV-side updates would ever fix. Every extraction-affecting
change bumps an internal `EXTRACTION_SCHEMA_VERSION` constant (`osv-client.js`),
stamped onto the shared sync-state record on every successful bootstrap/sync.
Direction matters:

- **Stored version missing or older than this pod's code**: normal upgrade path
  -- treated as never-bootstrapped, so the next cycle runs a full re-bootstrap
  against the current code. The in-memory blocklist is left empty in the
  meantime, the same accepted gap as any fresh pod start.
- **Stored version newer than this pod's code**: this pod is stale code starting
  up after something newer already took over -- it refuses to start
  (`process.exit(1)`) rather than run in a degraded state, since it has no
  correct way to interpret the current data shape.
- **Mid-operation, during a rolling deploy**: an already-running pod re-checks
  the shared version once per sync cycle (not once per package) before doing any
  write. If the shared state has since moved forward, that pod sits the cycle
  out rather than writing under a schema its own code no longer matches, but
  keeps serving reads fine from its already-loaded data.

Upgrading from no version marker at all (this mechanism's first-ever deploy) is
handled operationally, not automatically -- scale to a single replica for that
one transition.

## MAL confidence filtering

Not every `MAL-` advisory carries the same confidence signal. Each one carries
`database_specific.malicious-packages-origins[]` -- independent detectors
(source + advisory id) that flagged the package. As of this writing, roughly 18%
of npm `MAL-` records have zero recorded origins, most have exactly one, and the
rest have two or more. Sources seen in practice include `amazon-inspector`,
`ghsa-malware`, `reversing-labs`, `ossf-package-analysis`,
`google-open-source-security`, and `checkmarx`.

```yaml
filters:
  '@fortmesa/verdaccio-security-filter':
    osv:
      malware:
        minOrigin: 1 # only block if the advisory has at least this many origins
        sources: [] # optional allowlist of origin `source` values
```

**`osv.malware.minOrigin`** (default `1`) only blocks a `MAL-`-flagged package
if its advisory's origin count meets this minimum. **Known consequence of the
default**: zero-origin records are _not_ blocked by default -- a real behavior
difference from unconditionally blocking every non-withdrawn `MAL-` record. Set
to `0` to restore that unconditional behavior.

**`osv.malware.sources`** (default `[]`, disabled) optionally restricts blocking
to advisories with at least one origin whose `source` is in this list -- e.g.
`sources: [reversing-labs, checkmarx]` ignores advisories flagged only by other
sources. **Combines with `minOrigin` as independent AND**: the origin count is
computed over _all_ origins regardless of source; the source check (when
configured) is separate and only needs one matching origin.

## CVE (GHSA) blocking

OSV's npm feed also carries real CVE-backed vulnerability data, entirely
separate from the `MAL-` (confirmed-malicious) feed: several thousand `GHSA-`
records. `database_specific.severity` (`LOW`/`MODERATE`/`HIGH`/`CRITICAL`) and
`database_specific.cwe_ids[]` are present on the large majority of non-withdrawn
records; a `CVE-*` alias is present on most but not all (the rest are GHSA-only,
no CVE ever assigned). This reuses the same sync machinery as the `MAL-` feed
(bootstrap + incremental via `modified_id.csv`

- withdrawal handling) since both record types live in the same feed already
  being polled.

**Severity casing**: OSV's own bucket is uppercase; this plugin normalizes it to
lowercase (`low`/`moderate`/`high`/`critical`) at extraction time, to match
npm/yarn's own audit wire format rather than OSV's native casing.
`osv.cve.severity`/the per-CWE severity lists in `osv.cve.cwe` accept either
case in config -- both are normalized to lowercase before comparison, so
existing uppercase config keeps working unchanged.

**Range boundaries**: OSV's schema defines two mutually-exclusive ways a range
expresses its upper bound -- `fixed` (exclusive: versions >= fixed are safe) and
`last_affected` (inclusive: "versions above `last_affected` should be considered
unaffected"). Both are handled correctly. A small number of records carry
neither structured event, only a free-text, non-standard
`database_specific.last_known_affected_version_range` field (used when GHSA
never got a version with a real fix, e.g. `xlsx`) -- this is parsed on a
best-effort basis for simple `<`/`<=` forms only; anything more complex is left
unparsed and the range stays open, the same fail-closed behavior as any other
unparseable bound.

```yaml
filters:
  '@fortmesa/verdaccio-security-filter':
    osv:
      cve:
        severity: [] # e.g. [high, critical] -- blocks any CVE at these severities, any CWE
        cwe: [] # e.g. [CWE-79, {CWE-506: [critical, high]}, CWE-555]
        cvss3Min: null # e.g. 7.0 -- blocks any CVE with a computed CVSS v3.1 base score >= this
        cvss4Min: null # e.g. 7.0 -- blocks any CVE with a computed CVSS v4.0 base score >= this
```

All four default to disabled (`[]`/`null`) -- CVE data (including CVSS scores)
is still computed and synced whenever `osv.enabled: true` (there's no separate
enable flag, since it's the same feed), but CVE-based blocking is inert until at
least one of these is populated.

**`osv.cve.severity`** blocks any CVE at the listed severities, regardless of
CWE.

**`osv.cve.cwe`** is a **list** where each entry is either a bare CWE id string
(blocks at _any_ severity, ignoring `osv.cve.severity`) or a single-key mapping
`{CWE-id: [severities]}` (blocks only at that CWE's own severity list,
**overriding** `osv.cve.severity` for that specific CWE rather than combining
with it). For example, with:

```yaml
osv:
  cve:
    severity: [CRITICAL]
    cwe:
      - CWE-79
      - CWE-506:
          - CRITICAL
          - HIGH
```

a `LOW` CVE tagged `CWE-79` blocks regardless of severity (bare entry); a `HIGH`
CVE tagged `CWE-506` blocks via its own override list, but a `MODERATE` CVE
tagged `CWE-506` does **not** (`MODERATE` isn't in that CWE's own
`[CRITICAL, HIGH]` list, and the global `severity: [CRITICAL]` doesn't rescue it
either); a `CRITICAL` CVE tagged neither CWE still blocks via the global list.
The overall match is **OR** across all three: global severity match, or a
CWE-specific match.

At construction, `osv.cve.cwe` is normalized into an internal
`Map<cweId, severities[]>` for O(1) lookup at check time -- the list form above
is just the readable config surface. The same CWE id must not appear more than
once across the list (whether bare, keyed, or both) -- this is checked
explicitly and fails loud at startup if violated. `osv.cve.severity` entries and
every severity inside an `osv.cve.cwe` entry must be one of
`low`/`moderate`/`high`/`critical` (case-insensitive in config, normalized to
lowercase before validation) -- also checked at startup.

**`osv.cve.cvss3Min`/`osv.cve.cvss4Min`** block any CVE whose computed CVSS base
score meets or exceeds the configured minimum, independent of each other and of
severity/cwe -- same "either alone is sufficient to block" principle. Real npm
GHSA data only ever carries CVSS v3.1 and/or v4.0 vectors (never v2 or v3.0) --
the base score is computed once, at sync time, via the
[`ae-cvss-calculator`](https://www.npmjs.com/package/ae-cvss-calculator) library
rather than hand-rolled, since CVSS v4.0's scoring method is a MacroVector
lookup table, not a simple formula. Kept as two independent fields internally,
not collapsed into one -- `cvss3Min` only ever compares against a v3.1 score,
`cvss4Min` only against a v4.0 score; a record missing one version's vector
simply never matches that specific gate, with no fallback between them.

**A package's MAL and CVE data coexist independently** -- a package can be both
a confirmed-malicious `MAL-` package and separately have one or more tracked
CVEs (rare, but not prevented). `check()` evaluates the MAL dimension first
(gated by `osv.malware.minOrigin`/`osv.malware.sources`), then any CVE entries
(gated by
`osv.cve.severity`/`osv.cve.cwe`/`osv.cve.cvss3Min`/`osv.cve.cvss4Min`) -- any
one of these alone is sufficient to block a version.

## Storage backends

The OSV blocklist sync (`filesystem-store.js`, `redis-store.js`,
`dynamodb-store.js`) is pluggable -- the backend is **auto-selected** from
whichever of `osv.redis`/`osv.dynamo`/`osv.filesystem` is configured, in that
priority order (configure exactly one section). All three implement the same
small interface (`scanAll`/`getItem`/`putItem`/`putItems`/`deleteItem`/
`close`), so switching backends never touches the sync engine, `check()`, or any
of the MAL/CVE filtering logic above -- it's purely a storage-layer swap.

```yaml
filters:
  '@fortmesa/verdaccio-security-filter':
    osv:
      # dynamo -- picked when this section is present (checked before filesystem)
      dynamo:
        tableName: verdaccio-malicious-packages
        region: us-east-1
        keyPrefix: '' # optional, default '' -- prefix applied to every pk this plugin writes


      # filesystem -- picked when this section is present and neither redis nor dynamo is
      # filesystem:
      #   path: /verdaccio/osv-storage

      # redis -- picked when this section is present (highest priority)
      # redis:
      #   url: redis://localhost:6379
      #   keyPrefix: ""   # optional, default '' -- prefix applied to every key this plugin writes
```

Configure exactly one of `osv.redis`/`osv.dynamo`/`osv.filesystem`; if more than
one is present, priority is **redis > dynamo > filesystem**. Leaving
`osv.enabled: true` with none of the three configured fails loud at
construction.

**`dynamo`** -- requires `@aws-sdk/client-dynamodb` and `@aws-sdk/lib-dynamodb`
to be installed (see below). The DynamoDB table itself remains
partition-key-only (`pk`) -- `keyPrefix` namespaces the `pk` attribute value
itself (applied on write, stripped back off on read/scan) rather than a separate
outer key, since Dynamo has no key/value distinction to hang a prefix on the way
Redis does.

**`filesystem`** -- zero third-party dependencies (uses only Node's built-in
`fs`), one JSON file per package under `osv.filesystem.path`. Simplest option
for a small or dev deployment that doesn't want to provision Redis or DynamoDB
just to try the feature. No TTL/expiry -- same as the other two backends, this
data persists indefinitely. The directory must be on persistent (not ephemeral)
storage for the data to survive a restart, same consideration as any other
stateful volume.

**`redis`** -- requires `ioredis` to be installed (see below). Uses a single
client with no connection pool (nothing in this plugin does a blocking read,
unlike some Redis use cases). `scanAll()` uses `SCAN`, not `KEYS`, to avoid
blocking the server for the duration of a scan over a large keyspace. Bulk
writes are pipelined in chunks for throughput at bootstrap scale; a pipeline
failure fails every item in that chunk (all-or-nothing per chunk).

**Installing an optional backend's package**: `@aws-sdk/client-dynamodb`,
`@aws-sdk/lib-dynamodb`, and `ioredis` are `peerDependencies`, not regular
`dependencies` -- configuring `osv.redis` without `ioredis` installed (or
`osv.dynamo` without the AWS SDK packages) fails loudly at construction with an
actionable message telling you which package to install, rather than a raw
`Cannot find module` crash. An operator only needs to install the package for
the backend they actually chose.

## After blocking

- Blocked versions are deleted from `packageInfo.versions` and
  `packageInfo.time` entirely -- they don't show up in `npm view`, can't be
  installed by exact version, and don't count for range resolution. A version
  substituted via `strategy: replace` keeps its key instead (see
  [Manual block/allow lists](#manual-blockallow-lists-and-date-threshold)
  above).
- Any `dist-tags` entry (e.g. `latest`) that pointed at a version actually
  removed above is redirected to the newest remaining version, preferring a
  stable (non-prerelease) version if one exists -- a replaced version keeps its
  key, so its dist-tags are left alone.
- If every remaining version is also blocked for a given tag, that tag is
  removed entirely rather than left dangling.

## Publish-time gate

Everything above only ever hides an already-stored version from later reads --
it never touches the publish path. A malicious or compromised publish still
succeeds and lands in storage; the filter's read-time behavior just means nobody
can install the bad version.

Two independently-toggled flags close that gap, each **rejecting the
`npm publish` itself**, outright, before anything is written to storage:

```yaml
middlewares:
  '@fortmesa/verdaccio-security-filter':
    blockPublishWithNewScripts: false # install-script introduction
    blockPublishMatches: false # OSV blocklist / manual block: matches
```

**`blockPublishWithNewScripts`** rejects a version that introduces a
`preinstall`/`install`/`postinstall` script that no version already stored for
that package has -- see "How it determines 'new'" below for the exact mechanism.
Unlike the read-time check, there is no `packageAge.scriptCheckDays` grace
period here: at the moment of publish there's no history for the introduction to
have aged past, so any first-time introduction against an established clean
baseline is rejected every time (an `allow:`-listed package is still exempt,
same as the read-time check). A brand-new package or one that has _always_
shipped install scripts is never blocked, same as the read-time check.

**`blockPublishMatches`** rejects a version matching the OSV blocklist or a
manual `block:` rule (an `allow:` match still bypasses either). Unlike the
script check, this has **no "clean baseline" precondition** -- it fires even for
a brand-new package's very first publish, since a known-malicious or
manually-blocked match is an unconditional no regardless of history. `strategy`
on a matched `block:` rule is ignored at publish time (there's nothing yet to
substitute -- the write either happens or it doesn't).

Both apply to every package the registry accepts a publish for, since the check
runs on the publish route itself, before any `packages:` pattern-specific
handling. A manual `block:` rule naming an internal package is a legitimate
incident-response kill-switch (e.g. blocking republish of a compromised internal
package during remediation).

This requires the plugin to be listed under **both** `filters:` (for the
read-time behavior above) **and** `middlewares:` (for these gates) -- they're
loaded by Verdaccio as two independent plugin instances. The `block`/`allow`/
`webhook` settings themselves are read from the canonical
`filters: "@fortmesa/verdaccio-security-filter":` section of the full app config
regardless of which instance is evaluating them, so they don't need to be
duplicated under `middlewares:` too -- and must use that exact, literal scoped
key: Verdaccio resolves a scoped plugin's config key verbatim, with no
`verdaccio-` prefix mangling, so a bare `security-filter:` key here would never
match and this shared lookup would silently fall back to each instance's own
(much smaller) local config instead.

**How it determines "new"**: on a `PUT` to the publish route, it parses the
request body itself (this middleware runs before Verdaccio's own API router
installs its `express.json()` body parser -- see `register_middlewares()`'s
comments in `index.js` for exactly why re-parsing it here is safe and doesn't
break Verdaccio's own subsequent handling of the same request), diffs `versions`
in that body against the package's already-stored versions (via
`storage.getPackage()`), and checks only the version keys that aren't already
stored. This is robust to either shape npm sends (just the new version, or the
full merged set) and naturally leaves `npm deprecate`/`npm star` requests
untouched, since neither introduces a version key that isn't already stored.

## Audit / advisory endpoints

Real `npm audit`/`yarn npm audit` support -- both the modern and legacy wire
protocols, since different client majors use different ones and this plugin has
no control over which one a given install picks:

- `POST /-/npm/v1/security/advisories/bulk` -- npm 7+ and yarn berry 4.x.
- `POST /-/npm/v1/security/audits` and `POST /-/npm/v1/security/audits/quick` --
  npm 6 and yarn berry 2.x/3.x (`legacy-audit.js`). Confirmed directly against
  each client's own source, not assumed: npm 7's own `@npmcli/arborist` tries
  `advisories/bulk` first and only falls back to `audits/quick` if that request
  itself fails; npm 6 and yarn 2.x/3.x have no concept of `advisories/bulk` at
  all and call the older routes directly.

Both are registered unconditionally in `register_middlewares()`, regardless of
`blockPublishWithNewScripts`/`blockPublishMatches`/`osv.enabled` -- an
unconfigured/disabled OSV store just means every lookup comes back empty, the
same honest "nothing known" response as a real empty sync. **This still requires
the plugin to be listed under `middlewares:`** (see "Publish-time gate" above
for why that's a separate plugin instance from `filters:`) -- unlike the two
publish-time gates, no flag needs to be set true for these routes to exist, but
the section itself must be present:

```yaml
middlewares:
  '@fortmesa/verdaccio-security-filter': {}
```

**Why register a route at all, even an empty one**: leaving it unregistered
entirely (the alternative -- Verdaccio has no built-in route here unless its own
bundled `verdaccio-audit` plugin is separately configured) causes a real,
confirmed difference in client behavior on the resulting `404`: `npm audit`
degrades gracefully (a clean, informative error, exit code `1`), but yarn berry
4.x's `yarn npm audit` throws an uncaught exception and dumps a raw internal
stack trace instead. A valid `200` response, populated or not, avoids that crash
for every client.

**Response content**: both routes reuse the same CVE data `osv.cve.*` blocking
already computes (`vulnerableVersions`, severity, CWE ids, CVSS scores) --
**unfiltered** by this deployment's own `osv.cve.*` thresholds, since
`npm audit` exists to inform developers of everything known, independent of what
this deployment has chosen to actually block. **MAL** (confirmed-malicious
package) data is **not** included in either response yet -- serving it needs
dedicated compatibility testing against real npm/yarn/pnpm tooling first, to
confirm it doesn't break existing install/audit flows; deferred until that
testing happens.

**advisories/bulk** request/response is a flat `{name: [versions]}` in,
`{name: [advisory, ...]}` out -- npm's own client-side
`@npmcli/metavuln-calculator` `Advisory` class reads `id`/`severity` (defaults
`high`)/`vulnerable_versions` (defaults `*`) directly off each entry.

**audits(/quick)** is a materially different shape: the client submits its _own_
full dependency tree/graph in the request (npm 6's shrinkwrap-derived nested
tree, yarn berry's flat requires-graph -- both reduce to the same
`{requires, dependencies}` structure at every level), and the server has to walk
that submitted tree itself to find every occurrence of a flagged package, since
there's no simple name-to-versions map to look up. Every remediation entry in
the response's `actions` array is `action: 'review'`, never `update`/`install`
-- internally, a CVE's affected-range data is stored as a single OR'd semver
clause (`vulnerableVersions`), not a tracked first-patched-version, so there's
no reliable upgrade target to recommend automatically; recommending manual
review is the honest answer, not a placeholder for a harder feature. This does
**not** weaken the actual report: exit codes and vulnerability counts for both
routes are driven by `metadata.vulnerabilities` severity counts, which this
plugin populates correctly regardless of `actions`.

**yarn classic (1.x) cannot be reached by either route.** Confirmed directly
(`yarn audit --verbose`): yarn classic's `audit` command hardcodes its request
to the real `https://registry.yarnpkg.com/-/npm/v1/security/audits`, ignoring
whatever registry is actually configured. No route this plugin registers will
ever be reached by it -- this is a limitation of yarn classic itself, not
something a server-side change can fix.

**`npm audit fix`**: works correctly for npm 7-11 with no additional server-side
support needed -- confirmed by reading `@npmcli/arborist`'s own `Vuln` class and
by a live publish/pin/fix round-trip: the fix target is computed entirely
client-side, combining the `vulnerable_versions` range this plugin serves with
the package's real version list (fetched independently via the normal registry
packument). For npm 6, `npm audit fix` is a safe no-op -- its own fix logic only
acts on `update`/`install` actions, and this plugin only ever emits `review`
actions (see above), so it correctly reports and exits without silently changing
anything. **Yarn has no audit-fix equivalent to support at all** --
`yarn npm audit --help` confirms Yarn Berry never implemented automatic audit
remediation, on any major version.

## Webhooks

A single, static, operator-configured webhook target -- fired for every "loud"
(`error`-level, see "Logging" below) security event this plugin raises: the four
publish-time gate rejections above, plus the OSV-sync retroactive alert
described in "Malicious-package blocklist (OSV)". This is deliberately minimal
compared to a full pub/sub notification system: one config-defined URL, no
dynamic per-admin-created subscriptions, no SSRF surface to defend against --
`config.yaml` is the trust boundary here, same as `block:`/`allow:` above.

```yaml
filters:
  '@fortmesa/verdaccio-security-filter':
    webhook:
      url: https://example.com/hooks/verdaccio-security
      body: '{"pkg":"{{pkg}}","ver":"{{ver}}","event":"{{event}}","reason":"{{reason}}"}'
      content-type: application/json
      authorization: 'Bearer a-long-random-secret'
```

Like `block`/`allow`, this lives in the canonical
`filters: "@fortmesa/verdaccio-security-filter":` section and is shared by both
plugin instances.

**Shape**: `url` and `body` are the only two recognized keys. `body`'s presence
decides the HTTP method -- set it and the request is a `POST` with that body;
omit it and the request is a `GET` with no body (useful for a receiver that only
needs a ping, e.g. incrementing a counter). Every other key in the `webhook:`
block is sent as an HTTP header, verbatim: the YAML key becomes the header name,
the (substituted) value becomes the header value. There is no fixed header list
-- set `content-type`, `authorization`, `x-anything`, whatever the receiver
expects.

**Templating**: `url`, `body`, and every header value are template strings.
`{{name}}` is replaced with that field from the triggering event, or the empty
string if the event didn't carry that field. Every event carries at least
`event`, `pkg`, `ver`, and `reason` (the same human-readable sentence the
publish-time gate's own 403 response body uses, or an equivalent one for the OSV
retroactive alert); the four publish-time events also carry `user`; each event
additionally carries whichever of `cveId`/`severity`/`cweIds`/`malIds`/
`rule`/`scripts` apply to that specific reason (a manual `block:` match never
carries `cveId`, for instance). See `webhook.js`'s call sites in `index.js`/
`malicious-packages.js` for the exact field set per event.

**Delivery**: fire-and-forget. A failed delivery (network error, timeout,
non-2xx/3xx response) logs a `warn` and is otherwise ignored -- it never
retries, never queues, and never blocks or fails the publish/sync that triggered
it. A misconfigured `webhook.url` (missing entirely, or not a valid
`http`/`https` URL once template substitution runs) fails loud at plugin
construction (missing `url`) or logs an `error` and skips that one delivery
(invalid after substitution) -- either way, it never breaks the security
decision itself.

## Logging

Every read-time block and dist-tag redirect logs a `warn`-level line
(`security-filter: blocked -- ...` / `security-filter: dist-tag redirected ...`)
including the package name, version, and reason -- these are the lines to grep
for when a package unexpectedly fails to resolve to the version you expect. OSV
sync progress (bootstrap completion, a newly-applied or withdrawn advisory) also
logs at `warn`; a `304`/nothing-changed poll cycle logs nothing at all, since
it's the expected common case every poll interval and would otherwise be pure
noise.

A publish-time rejection is deliberately louder: it logs at **`fatal`** (not
`warn`) with a `security-filter: !!! BLOCKED PUBLISH !!! ...` line, including
the package, version, publishing user, and either the offending script
command(s) or the matched OSV advisory id(s)/block rule, for immediate forensic
value. This is an active attempt happening right now, not a passive wait-it-out
decision, so it's treated as a noteworthy failure rather than a normal
blocked/rejected/redirected one. Any OSV fetch or storage-backend failure during
sync also logs at `error`, for the ordinary reason: it's an unexpected failure,
not an active-attempt exception.

The OSV-sync retroactive alert (see "Malicious-package blocklist (OSV)") is
equally loud, at `fatal` with a
`security-filter: !!! CACHED PACKAGE NOW FLAGGED !!! ...` line -- distinct
wording from `BLOCKED PUBLISH` since nothing was actually published or actively
rejected at that moment; this is a passive discovery, not a live attempt, but no
less worth immediate attention. Both loud event families also fire the
configured `webhook:` (see "Webhooks" above), if any.

## Dependencies

`semver` -- version-range matching for manual `block:`/`allow:` rules and OSV
ranges, stable/prerelease detection, and sorting redirect/replace candidates.
`minimatch` -- `block:`/`allow:` pattern matching, the same convention Verdaccio
core (and every other plugin in this family) uses for package-name matching.
`body-parser` -- used only by the publish-time gates, to parse the request body
ahead of Verdaccio's own parsing; unused when both `blockPublishWithNewScripts`
and `blockPublishMatches` are left at their default `false`. `yauzl` -- streams
the OSV bootstrap zip without holding the whole archive decompressed in memory
at once. `ae-cvss-calculator` -- computes CVSS v3.1/v4.0 base scores for
`osv.cve.cvss3Min`/`cvss4Min` (see "CVE (GHSA) blocking" above); a regular
dependency, not an optional peer, since CVE data (including scores) is always
computed at sync time whenever `osv.enabled: true`, the same as severity/CWE.

`@aws-sdk/client-dynamodb`, `@aws-sdk/lib-dynamodb`, and `ioredis` are
**optional peer dependencies** (see [Storage backends](#storage-backends)
above), not regular dependencies -- only the one matching whichever of
`osv.redis`/`osv.dynamo`/`osv.filesystem` is actually configured needs to be
installed, and none of them are needed at all while `osv.enabled` is left at its
default `false`.
