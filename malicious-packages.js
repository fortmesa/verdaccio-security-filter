'use strict';

// Maintains the OSV-sourced malicious-package blocklist: a background sync
// job (see runSyncCycle()) keeps a storage backend current, and every pod
// keeps its own full in-memory copy (see check()) so a request never has to
// touch that backend or the network -- see docs/plugins/security-filter.md's
// "Cost characteristics" section for the numbers behind that design.
//
// The backend itself is pluggable (filesystem/redis/dynamo, auto-selected
// by pickStorageKind() below from whichever osv.redis/osv.dynamo/
// osv.filesystem section is configured -- see docs/plugins/security-filter.md's
// "Storage backends" section) -- this file only ever talks to the small common interface
// {scanAll, getItem, putItem, putItems, deleteItem, close} that
// filesystem-store.js/redis-store.js/dynamodb-store.js each implement, via
// this.store. It has no backend-specific knowledge of its own.
//
// filters: security-filter: and middlewares: security-filter: are two
// independent plugin instances (Verdaccio's loader instantiates each
// config-section entry separately), but there must be exactly one sync loop
// and one in-memory table per pod -- getAdvisoryStore() is a module-level
// singleton factory both instances call into, so whichever constructs first
// creates it and the second just reuses it.

const semver = require('semver');
const osvClient = require('./osv-client');
const {sendWebhook} = require('./webhook');

const SYNC_STATE_KEY = '__sync_state__'; // safe: npm forbids package names starting with '_'

// -1: stored is older than (or absent relative to) this code's own
//     osvClient.EXTRACTION_SCHEMA_VERSION -- self-heal via a full re-bootstrap.
//  0: stored matches this code's version -- safe to proceed normally.
//  1: stored is NEWER than this code's version -- some other, already-
//     upgraded instance has moved the shared state forward. At startup this
//     means refusing to run (see _warmStart()); mid-operation it means
//     sitting out this sync cycle (see runSyncCycle()) rather than writing
//     under a schema this code's own extraction logic no longer matches.
function compareSchemaVersion(storedVersion) {
  if (storedVersion == null) return -1;
  if (storedVersion === osvClient.EXTRACTION_SCHEMA_VERSION) return 0;
  return storedVersion < osvClient.EXTRACTION_SCHEMA_VERSION ? -1 : 1;
}
// Lowercase is the canonical internal form -- matches npm/yarn's own audit
// wire format (severity is lowercase there), not OSV's native uppercase
// bucket. Both OSV data (extractCveRecord in osv-client.js) and config
// values (parseCveSeverities below) are normalized to this before ever
// being compared, so operators can keep writing either case in config.
const KNOWN_SEVERITIES = new Set(['low', 'moderate', 'high', 'critical']);

// Storage backend is auto-selected from whichever of osv.redis/osv.dynamo/
// osv.filesystem is actually configured, in this priority order -- no
// explicit osvStorage: 'kind' switch to keep in sync with the section you
// actually filled in. Checked only once osv.enabled is true (see
// constructor below): a disabled, unconfigured OSV block is the normal
// default state, not a config mistake.
function pickStorageKind(config) {
  if (config.redis) return 'redis';
  if (config.dynamo) return 'dynamo';
  if (config.filesystem) return 'filesystem';
  throw new Error(
    'security-filter: osv.enabled is true but none of osv.redis / osv.dynamo / osv.filesystem is configured',
  );
}

// vulnerableVersions is a real semver range string, precomputed ONCE at
// import time by osv-client.js's toVulnerableVersions() -- the exact same
// fail-closed boundary handling that used to live here (an unparseable
// bound is omitted rather than embedded as a literal invalid clause) now
// happens once there, not on every single check. A whole-package block is
// just a "*" range -- no separate code path for "whole package" vs
// "specific versions". `includePrerelease: true` because OSV ranges are
// meant to also catch prerelease versions of an affected line, which plain
// semver.satisfies() otherwise excludes from a range with no prerelease
// tag of its own.
function versionSatisfies(version, vulnerableVersions) {
  const parsed = semver.valid(version) ?? semver.valid(semver.coerce(version));
  if (!parsed) return true; // can't parse the version of an already-flagged package -- fail closed
  return semver.satisfies(parsed, vulnerableVersions, {
    includePrerelease: true,
  });
}

function parseNonNegativeInt(value, name) {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(
      `security-filter: ${name} must be a non-negative integer, got ${JSON.stringify(value)}`,
    );
  }
  return value;
}

// osv.cve.cvss3Min/osv.cve.cvss4Min -- a minimum-threshold config, same
// shape as osv.malware.minOrigin, not a list like osv.cve.severity (a
// continuous score has no discrete enum to list). null (the default) means
// disabled -- matches osv.cve.severity/osv.cve.cwe's own "empty list ->
// disabled" convention.
function parseCvssMin(value, name) {
  if (value == null) return null;
  if (typeof value !== 'number' || value < 0 || value > 10) {
    throw new Error(
      `security-filter: ${name} must be a number between 0 and 10, got ${JSON.stringify(value)}`,
    );
  }
  return value;
}

function parseCveSeverities(list, source) {
  const normalized = list.map(sev =>
    typeof sev === 'string' ? sev.toLowerCase() : sev,
  );
  for (const sev of normalized) {
    if (!KNOWN_SEVERITIES.has(sev)) {
      throw new Error(
        `security-filter: ${source} has unknown severity '${sev}' -- must be one of ${Array.from(KNOWN_SEVERITIES).join(', ')}`,
      );
    }
  }
  return normalized;
}

// Normalizes the osv.cve.cwe config list -- entries are either a bare CWE id
// string (matches at ANY severity) or a single-key {CWE-id: [severities]}
// object (matches only at that CWE's own severity list, overriding the
// global osv.cve.severity for that CWE) -- into a Map<cweId, severities[]> for
// O(1) lookup at check() time. The list form is just the readable config
// surface; a Map is used at runtime since, unlike a list, it structurally
// rules out the same CWE id being listed twice with conflicting severities
// (still checked explicitly below, since a list doesn't prevent it).
function parseCweRules(list, source) {
  const rules = new Map();
  for (const entry of list) {
    let cweId;
    let severities;
    if (typeof entry === 'string') {
      cweId = entry;
      severities = [];
    } else if (entry && typeof entry === 'object') {
      const keys = Object.keys(entry);
      if (keys.length !== 1) {
        throw new Error(
          `security-filter: ${source} entry must have exactly one CWE id key: ${JSON.stringify(entry)}`,
        );
      }
      [cweId] = keys;
      severities = entry[cweId];
      if (!Array.isArray(severities)) {
        throw new Error(
          `security-filter: ${source} entry for '${cweId}' must map to an array of severities`,
        );
      }
    } else {
      throw new Error(
        `security-filter: ${source} entry must be a CWE id string or a {cweId: [severities]} object: ${JSON.stringify(entry)}`,
      );
    }
    severities = parseCveSeverities(
      severities,
      `${source} entry for '${cweId}'`,
    );
    if (rules.has(cweId)) {
      throw new Error(
        `security-filter: ${source} lists '${cweId}' more than once`,
      );
    }
    rules.set(cweId, severities);
  }
  return rules;
}

class MaliciousPackageStore {
  // `config` is the nested `osv:` sub-object of filters.security-filter
  // (i.e. security-filter.osv), not the whole security-filter section.
  constructor(config, options) {
    this.logger = options.logger;
    this.enabled = config.enabled ?? false;
    this._blocklist = new Map(); // packageName -> { ranges, malIds, originCount, sources, cves }
    this._timer = null;

    // Fired when an incremental sync's newly-applied delta matches a
    // version this registry already has cached/stored locally -- see
    // _checkAgainstLocalStorage() below. Same single, static webhook target
    // index.js's publish-time gate uses (threaded through by whichever
    // plugin instance constructs this singleton first -- see index.js's
    // getAdvisoryStore() call).
    this.webhookConfig = options.webhookConfig ?? null;
    // Only set once this plugin is ALSO configured under `middlewares:` (see
    // index.js's register_middlewares(), the only Verdaccio hook that
    // actually receives a `storage` reference) -- null until then, which
    // _checkAgainstLocalStorage() treats as "nothing to check against yet"
    // rather than an error: the passive read-path filter still catches these
    // cases regardless, this is only the proactive notification on top.
    this.registryStorage = null;

    // MAL confidence filters and CVE (GHSA) blocking config -- validated
    // unconditionally, even if osv.enabled is still false, so a config
    // mistake (e.g. a severity typo) fails loud immediately rather than
    // silently doing nothing until an operator later flips osv.enabled on.
    const malware = config.malware ?? {};
    const cve = config.cve ?? {};
    this.malOriginCountMin = parseNonNegativeInt(
      malware.minOrigin ?? 1,
      'osv.malware.minOrigin',
    );
    this.malSources = malware.sources ?? [];
    this.cveSeverities = parseCveSeverities(
      cve.severity ?? [],
      'osv.cve.severity',
    );
    this.cweRules = parseCweRules(cve.cwe ?? [], 'osv.cve.cwe');
    this.cvss3Min = parseCvssMin(cve.cvss3Min, 'osv.cve.cvss3Min');
    this.cvss4Min = parseCvssMin(cve.cvss4Min, 'osv.cve.cvss4Min');

    if (!this.enabled) return; // inert: check() always returns null, no storage client, no timers, no HTTP calls

    // Storage backend selection -- see docs/plugins/security-filter.md's
    // "Storage backends" section.
    this.storageKind = pickStorageKind(config);

    this.pollIntervalMs = (config.pollSeconds ?? 900) * 1000;
    this.pollJitterMs = (config.pollJitter ?? 90) * 1000;
    this.baseUrl =
      config.baseUrl ??
      'https://osv-vulnerabilities.storage.googleapis.com/npm/';
    this.requestTimeoutMs = (config.requestTimeoutSeconds ?? 30) * 1000;

    this.store =
      options.store ?? this._createStore(this.storageKind, config, options);

    this._bootstrapCompletedAt = null;
    this._bootstrapAttempt = 0;
    this._lastSyncedModifiedId = null;
    this._csvEtag = null;
    this._csvLastModified = null;

    // Test-only: skip the recurring timer entirely so tests can drive
    // runSyncCycle() manually with no background interference. Always true
    // in production.
    this._autoSchedule = options.autoSchedule ?? true;

    // Test-only: real process.exit() would kill the whole test runner the
    // moment a test exercises the "stored data is newer than this code"
    // path in _warmStart() -- injectable so tests can observe the call
    // instead of actually terminating.
    this._exitProcess = options.exitProcess ?? (code => process.exit(code));

    // Exposed so tests can await deterministic warm-start completion; never
    // awaited in production -- Verdaccio's loader does not await plugin
    // construction, so a pod may serve a few seconds of traffic before this
    // resolves (see docs/plugins/security-filter.md's accepted-gap note).
    this.ready = this._warmStart()
      .catch(err =>
        this.logger.error(
          {err: err.message},
          'security-filter: osv -- startup scan failed, starting with an empty in-memory list',
        ),
      )
      .finally(() => {
        if (this._autoSchedule) this._scheduleNext();
      });
  }

  // Called from index.js's register_middlewares() -- the only Verdaccio
  // hook that actually receives a `storage` reference. Idempotent/last-
  // writer-wins on purpose: harmless if called more than once (e.g. by a
  // pod restart) or never at all (retroactive checking below just stays
  // inert; nothing else depends on this).
  attachRegistryStorage(storage) {
    this.registryStorage = storage;
  }

  // Loads the requested backend module. filesystem-store.js has zero
  // optional dependencies, so it's required unconditionally; redis-store.js
  // and dynamodb-store.js each carry one, so they're loaded via
  // _requireOptional() -- deferring the require() until this exact branch
  // runs is what keeps a filesystem-only install from ever needing to
  // resolve 'ioredis' or the AWS SDK at all.
  _createStore(kind, config, options) {
    if (kind === 'filesystem') {
      return require('./filesystem-store').createFilesystemStore(
        config.filesystem,
      );
    }
    if (kind === 'redis') {
      return this._requireOptional('./redis-store', 'ioredis').createRedisStore(
        config.redis,
        options,
      );
    }
    return this._requireOptional(
      './dynamodb-store',
      '@aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb',
    ).createDynamoDbStore(config.dynamo, options);
  }

  // Rethrows a missing-optional-dependency require() failure with an
  // actionable message. Node doesn't distinguish "the required module
  // itself is missing" from "something the required module requires is
  // missing" -- both surface as MODULE_NOT_FOUND on the outer require()
  // call -- so this only ever fires for the intended case here, since
  // redis-store.js/dynamodb-store.js themselves always exist.
  _requireOptional(modulePath, packageHint) {
    try {
      return require(modulePath);
    } catch (err) {
      if (err.code === 'MODULE_NOT_FOUND') {
        throw new Error(
          `security-filter: osv.${this.storageKind} requires ${packageHint} -- run \`yarn add ${packageHint}\` in verdaccio-security-filter/`,
        );
      }
      throw err;
    }
  }

  // For the advisories/bulk endpoint (index.js) -- deliberately UNFILTERED
  // by osv.cve.severity/osv.cve.cwe/etc, unlike check() below. npm audit/
  // yarn npm audit exist to inform developers of everything OSV actually
  // knows about, a fundamentally different job than this deployment's own
  // auto-block policy -- a low-severity CVE this operator hasn't configured
  // to block is still real, useful information for `npm audit` to surface.
  // MAL (malicious-package) entries are deliberately excluded here --
  // representing one as a synthetic npm advisory needs its own dedicated
  // real npm/yarn/pnpm compatibility testing before it's included (see
  // docs/configuration.md's "Audit / advisory endpoints" section).
  getCveAdvisories(name) {
    return this._blocklist.get(name)?.cves ?? [];
  }

  // Hot path: zero network/storage calls, a plain Map lookup plus a small
  // semver comparison. This is what filter_metadata()/the publish gate call
  // on every single request. Checks the MAL dimension first (gated by
  // osv.malware.minOrigin/osv.malware.sources), then any CVE entries (gated
  // by osv.cve.severity/osv.cve.cwe) -- an entry can carry either, neither, or both.
  check(name, version) {
    const entry = this._blocklist.get(name);
    if (!entry) return null;

    if (
      entry.vulnerableVersions &&
      versionSatisfies(version, entry.vulnerableVersions) &&
      this._malPassesConfidenceFilters(entry)
    ) {
      return {type: 'mal', malIds: entry.malIds};
    }

    for (const cve of entry.cves ?? []) {
      if (!this._cveVersionAffected(version, cve)) continue;
      if (this._cveMatchesFilters(cve)) {
        return {
          type: 'cve',
          ids: [cve.id],
          cveId: cve.cveId,
          severity: cve.severity,
          cweIds: cve.cweIds,
          cvss3Score: cve.cvss3Score,
          cvss4Score: cve.cvss4Score,
        };
      }
    }

    return null;
  }

  // originCount/osv.malware.sources combine as independent AND: count is
  // computed over ALL origins regardless of source; the source check (when
  // osv.malware.sources is non-empty) is separate and requires only one match.
  _malPassesConfidenceFilters(entry) {
    if ((entry.originCount ?? 0) < this.malOriginCountMin) return false;
    if (
      this.malSources.length > 0 &&
      !(entry.sources ?? []).some(s => this.malSources.includes(s))
    )
      return false;
    return true;
  }

  // vulnerableVersions already folds in both the range-based and explicit
  // exact-version forms a CVE record can mix across affected[] entries
  // (see osv-client.js's toVulnerableVersions()) -- one check covers both.
  _cveVersionAffected(version, cve) {
    return (
      !!cve.vulnerableVersions &&
      versionSatisfies(version, cve.vulnerableVersions)
    );
  }

  // OR across every configured dimension: the global severity gate, a
  // CWE-specific gate, or either CVSS score minimum. A bare osv.cve.cwe
  // entry (empty severities array) matches at ANY severity, overriding the
  // global list for that CWE; a non-empty severities array on a CWE entry
  // replaces the global list for that CWE rather than being combined with
  // it. cvss3Min/cvss4Min are independent of each other and of
  // severity/cwe -- same "either alone is sufficient to block" principle.
  _cveMatchesFilters(cve) {
    if (
      this.cveSeverities.length === 0 &&
      this.cweRules.size === 0 &&
      this.cvss3Min == null &&
      this.cvss4Min == null
    )
      return false; // everything disabled
    if (cve.severity && this.cveSeverities.includes(cve.severity)) return true;
    for (const cweId of cve.cweIds ?? []) {
      if (!this.cweRules.has(cweId)) continue;
      const severities = this.cweRules.get(cweId);
      if (severities.length === 0) return true; // bare -- any severity
      if (cve.severity && severities.includes(cve.severity)) return true;
    }
    if (
      this.cvss3Min != null &&
      cve.cvss3Score != null &&
      cve.cvss3Score >= this.cvss3Min
    )
      return true;
    if (
      this.cvss4Min != null &&
      cve.cvss4Score != null &&
      cve.cvss4Score >= this.cvss4Min
    )
      return true;
    return false;
  }

  // Full scan over the whole backend, run once at construction so a
  // freshly-started/newly-scaled pod doesn't have to wait for a full poll
  // cycle before OSV-based blocking is active.
  //
  // Guards against a schema mismatch: modified_id.csv's watermark only
  // tells us whether OSV's *data* changed, never whether this plugin's own
  // extraction logic did -- an older version's stored items (e.g.
  // uppercase severity, no cvss3Score/cvss4Score, a last_affected range
  // silently treated as unbounded) would otherwise sit there uncorrected
  // indefinitely, only ever fixed by coincidence if that specific advisory
  // happens to receive a fresh OSV-side update. Direction matters here,
  // unlike the mid-operation check in runSyncCycle():
  //  - missing/older stored version: this pod is the newer code arriving
  //    to find older or no data -- self-heal via a full re-bootstrap.
  //    Existing items are deliberately left unloaded in the meantime -- an
  //    empty in-memory blocklist until bootstrap completes is the same
  //    accepted gap as any other fresh pod start, and safer than serving
  //    data this version can't fully trust.
  //  - newer stored version: this pod is stale code starting up *after*
  //    something newer already took over -- it has no correct way to
  //    interpret the current shape, so it refuses to start at all rather
  //    than run (or worse, write) in a degraded state that would only look
  //    healthy from the outside.
  async _warmStart() {
    const items = await this.store.scanAll();
    const stateItem = items.find(item => item.pk === SYNC_STATE_KEY);
    const cmp = compareSchemaVersion(stateItem?.extractionSchemaVersion);

    if (cmp === 1) {
      this.logger.fatal(
        {
          storedVersion: stateItem.extractionSchemaVersion,
          currentVersion: osvClient.EXTRACTION_SCHEMA_VERSION,
        },
        'security-filter: osv -- stored data was written by a NEWER extraction schema (@{storedVersion} > @{currentVersion}) than this pod is running -- refusing to start',
      );
      this._exitProcess(1);
      return; // real process.exit() never returns; this only matters for the injected test double
    }

    if (cmp === 0) {
      this._bootstrapCompletedAt = stateItem.bootstrapCompletedAt ?? null;
      this._lastSyncedModifiedId = stateItem.lastSyncedModifiedId ?? null;
      this._csvEtag = stateItem.csvEtag ?? null;
      this._csvLastModified = stateItem.csvLastModified ?? null;
      for (const item of items) {
        if (item.pk !== SYNC_STATE_KEY) this._applyToMemory(item);
      }
      return;
    }

    // cmp === -1: missing or older -- self-heal via a full re-bootstrap.
    // _bootstrapCompletedAt/_lastSyncedModifiedId/_csvEtag/_csvLastModified
    // are already null from the constructor -- left untouched here so the
    // next runSyncCycle() takes the bootstrap branch.
    if (stateItem) {
      this.logger.warn(
        {
          storedVersion: stateItem.extractionSchemaVersion ?? '(none)',
          currentVersion: osvClient.EXTRACTION_SCHEMA_VERSION,
        },
        'security-filter: osv -- stored data was written by an older extraction schema (@{storedVersion} vs @{currentVersion}), forcing a full re-bootstrap',
      );
    }
  }

  // Jitter applies to every tick, including the very first one after
  // warm-start -- so if both replicas start at the same time, their sync
  // cycles don't align. No leader election between replicas: every write
  // below is idempotent, so both pods syncing independently just means some
  // harmless redundant work, not a correctness issue.
  _scheduleNext() {
    const jitter = (Math.random() * 2 - 1) * this.pollJitterMs;
    // The very first bootstrap attempt (never tried yet) fires essentially
    // immediately -- zero protection until it completes is worse than any
    // delay could justify. Only a *failed* bootstrap attempt backs off, on a
    // faster capped schedule than waiting a full poll interval between tries.
    let baseDelay;
    if (this._bootstrapCompletedAt) {
      baseDelay = this.pollIntervalMs;
    } else if (this._bootstrapAttempt === 0) {
      baseDelay = 0;
    } else {
      baseDelay = Math.min(
        this.pollIntervalMs,
        30000 * 2 ** (this._bootstrapAttempt - 1),
      );
    }
    const delay = Math.max(0, baseDelay + jitter);
    this._timer = setTimeout(() => {
      this.runSyncCycle()
        .catch(err =>
          this.logger.warn(
            {err: err.message},
            'security-filter: osv -- sync cycle failed',
          ),
        )
        .finally(() => this._scheduleNext());
    }, delay);
    this._timer.unref?.(); // don't keep the process (or a test run) alive solely for this timer
  }

  // One version check per cycle, not one per package -- a race with some
  // other, already-upgraded instance mid-cycle is unlikely, and even if it
  // happens the affected package(s) either get retried next cycle
  // (incremental) or get overwritten again once a bulk resync elsewhere
  // finishes (which runs slower than an incremental cycle anyway, so it's
  // still the one that lands last). Not worth a getItem() per package to
  // guard against.
  async runSyncCycle() {
    const stateItem = await this.store.getItem(SYNC_STATE_KEY);
    if (compareSchemaVersion(stateItem?.extractionSchemaVersion) === 1) {
      this.logger.warn(
        {
          storedVersion: stateItem.extractionSchemaVersion,
          currentVersion: osvClient.EXTRACTION_SCHEMA_VERSION,
        },
        'security-filter: osv -- shared state has moved to a newer extraction schema (@{storedVersion} > @{currentVersion}) since this pod started -- skipping this sync cycle',
      );
      return;
    }

    if (!this._bootstrapCompletedAt) {
      this._bootstrapAttempt += 1;
      await this._runBootstrap();
    } else {
      await this._runIncrementalSync();
    }
  }

  // First-ever run (the backend has no bootstrapCompletedAt yet): walk the
  // entire OSV npm feed once, bulk-write minimal records, then seed the
  // modified_id.csv watermark so steady-state sync starts from here.
  //
  // A package's MAL and CVE data can land on the same backend item, and
  // putItems() replaces the WHOLE item (no partial merge) -- so records are
  // first fully accumulated in memory (merging by package name as
  // encountered, regardless of which order MAL/GHSA records for the same
  // package appear in the zip), and only written to the backend once the
  // entire stream has been consumed. This isn't a new memory cost: the
  // finished blocklist already lives in memory permanently after bootstrap
  // (see _applyToMemory) -- this just realizes that same footprint slightly
  // earlier, before writes start rather than only after.
  async _runBootstrap() {
    let maxModified = null;
    const staging = new Map(); // pkgName -> item, merged across MAL + CVE records

    try {
      for await (const record of osvClient.fetchAllRecords({
        baseUrl: this.baseUrl,
        timeoutMs: this.requestTimeoutMs,
        logger: this.logger,
      })) {
        // Bootstrap builds from scratch -- a withdrawn record (no `packages`
        // field; extractMinimalRecord() returns just {id, withdrawn: true})
        // has nothing to withdraw yet, so it's simply never included.
        if (record.withdrawn) continue;
        if (!maxModified || record.modified > maxModified)
          maxModified = record.modified;

        const isMal = osvClient.isMalRecord(record.id);
        for (const pkg of record.packages) {
          const item = staging.get(pkg.name) ?? {pk: pkg.name};
          if (isMal) {
            item.vulnerableVersions = pkg.vulnerableVersions;
            item.malIds = [record.id];
            item.originCount = pkg.originCount;
            item.sources = pkg.sources;
          } else {
            item.cves = (item.cves ?? []).concat({
              id: record.id,
              cveId: record.cveId,
              severity: record.severity,
              cweIds: record.cweIds,
              cvss3Score: record.cvss3Score,
              cvss4Score: record.cvss4Score,
              vulnerableVersions: pkg.vulnerableVersions,
            });
          }
          item.modified = record.modified;
          staging.set(pkg.name, item);
        }
      }
    } catch (err) {
      this.logger.warn(
        {err: err.message},
        'security-filter: osv -- bootstrap failed, will retry',
      );
      return; // don't set bootstrapCompletedAt -- next tick retries from scratch
    }

    const items = Array.from(staging.values());
    const count = items.length;
    const unwritten = await this.store.putItems(items);
    const failedKeys = new Set(unwritten.map(it => it.pk));
    for (const item of items) {
      if (!failedKeys.has(item.pk)) this._applyToMemory(item);
    }
    const failedCount = failedKeys.size;

    // Seed the CSV etag/high-water-mark so steady-state sync starts here,
    // rather than re-deriving it from a separate first incremental cycle.
    let csvEtag = null;
    let csvLastModified = null;
    try {
      const csvResult = await osvClient.fetchModifiedCsv({
        baseUrl: this.baseUrl,
        timeoutMs: this.requestTimeoutMs,
      });
      if (!csvResult.notModified) {
        csvEtag = csvResult.etag;
        csvLastModified = csvResult.lastModified;
        if (
          csvResult.rows.length > 0 &&
          (!maxModified || csvResult.rows[0].modified > maxModified)
        ) {
          maxModified = csvResult.rows[0].modified;
        }
      }
    } catch (err) {
      this.logger.warn(
        {err: err.message},
        'security-filter: osv -- failed to seed modified_id.csv state after bootstrap',
      );
    }

    this._bootstrapCompletedAt = new Date().toISOString();
    this._lastSyncedModifiedId = maxModified;
    this._csvEtag = csvEtag;
    this._csvLastModified = csvLastModified;
    await this._writeSyncState();

    if (failedCount > 0) {
      this.logger.error(
        {count, failedCount},
        'security-filter: osv -- bootstrap completed with unwritten entries, @{failedCount} of @{count} failed',
      );
    } else {
      this.logger.info(
        {count},
        'security-filter: osv -- bootstrap completed, @{count} entries loaded',
      );
    }
  }

  // Steady-state: conditional GET on modified_id.csv. A 304 means nothing
  // changed since last cycle -- the literal "know when to recheck based on
  // HTTP not-modified status" requirement -- and ends the cycle with zero
  // further work and zero backend calls.
  async _runIncrementalSync() {
    let csvResult;
    try {
      csvResult = await osvClient.fetchModifiedCsv({
        baseUrl: this.baseUrl,
        etag: this._csvEtag,
        lastModified: this._csvLastModified,
        sinceModified: this._lastSyncedModifiedId,
        timeoutMs: this.requestTimeoutMs,
      });
    } catch (err) {
      this.logger.warn(
        {err: err.message},
        'security-filter: osv -- failed to check modified_id.csv, will retry next cycle',
      );
      return;
    }

    if (csvResult.notModified) return;

    const {rows, etag, lastModified} = csvResult;
    if (rows.length === 0) {
      // The file changed but nothing is newer than our own high-water-mark
      // (e.g. non-MAL churn already behind our mark) -- just persist the
      // new etag/lastModified so the next check is a clean 304 comparison.
      this._csvEtag = etag;
      this._csvLastModified = lastModified;
      await this._writeSyncState();
      return;
    }

    let allApplied = true;
    for (const row of rows) {
      const isMal = osvClient.isMalRecord(row.id);
      if (!isMal && !osvClient.isCveRecord(row.id)) continue; // still counts toward the high-water-mark below
      try {
        const record = await osvClient.fetchRecord(row.id, {
          baseUrl: this.baseUrl,
          timeoutMs: this.requestTimeoutMs,
        });
        if (!record) continue;
        if (record.withdrawn) {
          await this._handleWithdrawal(record.id);
          continue;
        }
        for (const pkg of record.packages) {
          const applied = await this._upsertPackage(
            pkg.name,
            isMal
              ? {
                  vulnerableVersions: pkg.vulnerableVersions,
                  malIds: [record.id],
                  originCount: pkg.originCount,
                  sources: pkg.sources,
                }
              : {
                  cveEntry: {
                    id: record.id,
                    cveId: record.cveId,
                    severity: record.severity,
                    cweIds: record.cweIds,
                    cvss3Score: record.cvss3Score,
                    cvss4Score: record.cvss4Score,
                    vulnerableVersions: pkg.vulnerableVersions,
                  },
                },
          );
          if (!applied) {
            allApplied = false;
            continue;
          }
          this.logger.info(
            isMal
              ? {pkg: pkg.name, malIds: [record.id]}
              : {
                  pkg: pkg.name,
                  cveId: record.cveId ?? record.id,
                  severity: record.severity,
                  cweIds: record.cweIds,
                },
            isMal
              ? 'security-filter: osv -- new malicious-package advisory applied for @{pkg} (@{malIds})'
              : 'security-filter: osv -- new CVE advisory applied for @{pkg} (@{cveId}, @{severity})',
          );
        }
      } catch (err) {
        allApplied = false;
        this.logger.error(
          {id: row.id, err: err.message},
          'security-filter: osv -- failed to fetch/apply changed record',
        );
      }
    }

    // All-or-nothing per cycle: only advance the watermark/etag if every
    // changed record this cycle was applied successfully. A failure leaves
    // the mark where it was, so next cycle re-diffs the same window and
    // retries -- safe, since every upsert here is idempotent.
    if (allApplied) {
      this._lastSyncedModifiedId = rows[0].modified; // rows are newest-first
      this._csvEtag = etag;
      this._csvLastModified = lastModified;
      await this._writeSyncState();
    }
  }

  // Read-modify-write for a single changed package during incremental sync:
  // fetches the existing item (if any) so a MAL update never clobbers that
  // package's existing cves[] and vice versa -- putItems() replaces the
  // whole item, so the merge has to happen before that write, not after.
  // Unlike bootstrap, incremental volume is a handful of records per cycle,
  // so the extra getItem() per changed record is negligible and doesn't
  // touch the "backend only touched by the background job" guarantee.
  async _upsertPackage(pkgName, delta) {
    let existing;
    try {
      existing = (await this.store.getItem(pkgName)) ?? {pk: pkgName};
    } catch (err) {
      this.logger.error(
        {pkg: pkgName, err: err.message},
        'security-filter: osv -- failed to read existing item before merge',
      );
      return false;
    }

    const merged = {...existing, pk: pkgName};
    if (delta.cveEntry) {
      merged.cves = (existing.cves ?? [])
        .filter(c => c.id !== delta.cveEntry.id)
        .concat(delta.cveEntry);
    } else {
      merged.vulnerableVersions = delta.vulnerableVersions;
      merged.malIds = delta.malIds;
      merged.originCount = delta.originCount;
      merged.sources = delta.sources;
    }
    merged.modified = new Date().toISOString();

    const unwritten = await this.store.putItems([merged]);
    if (unwritten.length > 0) return false;
    this._applyToMemory(merged);
    this._checkAgainstLocalStorage(pkgName, delta);
    return true;
  }

  // Cross-references a just-applied incremental delta (NOT the package's
  // whole merged entry -- a pre-existing entry that already matched a
  // cached version would already have been notified about on some earlier
  // cycle, when that entry was itself the delta) against whatever this
  // registry actually has cached/stored locally, so a genuinely new match
  // is noticed and alerted on immediately rather than silently waiting for
  // some future client to coincidentally request that exact package again
  // (which is the only thing that would otherwise surface it, via the
  // ordinary, quiet filter_metadata() path in index.js).
  //
  // Deliberately NOT called from _runBootstrap(): that's a one-time,
  // whole-history initial load (the entire OSV feed, potentially thousands
  // of entries) -- treating every entry as "new" there would mean a flood
  // of alerts on a fresh pod's first boot for advisories that predate this
  // registry ever caching anything, which is noise, not signal. Steady-
  // state incremental syncs are where "new OSV data" genuinely means new.
  _checkAgainstLocalStorage(pkgName, delta) {
    if (!this.registryStorage) return; // not attached yet -- see attachRegistryStorage()

    this.registryStorage.getPackage({
      name: pkgName,
      uplinksLook: false, // local storage only -- never triggers an uplink fetch
      callback: (err, pkg) => {
        if (err || !pkg?.versions) return; // not cached locally -- nothing to alert on

        for (const ver of Object.keys(pkg.versions)) {
          if (delta.cveEntry) {
            if (
              !this._cveVersionAffected(ver, delta.cveEntry) ||
              !this._cveMatchesFilters(delta.cveEntry)
            )
              continue;
            const {cveId, severity, cweIds} = delta.cveEntry;
            const reason =
              `SECURITY ALERT: ${pkgName}@${ver}, already cached in this registry, now matches known ` +
              `vulnerability ${cveId ?? delta.cveEntry.id} (${severity ?? 'unknown severity'}` +
              `${cweIds?.length ? ', ' + cweIds.join(', ') : ''}) from OSV.`;
            this.logger.fatal(
              {pkg: pkgName, ver, cveId, severity, cweIds},
              'security-filter: !!! CACHED PACKAGE NOW FLAGGED !!! @{pkg}@@{ver} matches known vulnerability ' +
                '@{cveId} [@{severity}, @{cweIds}] (OSV) -- already in local storage',
            );
            sendWebhook(
              this.webhookConfig,
              {
                event: 'osv_retroactive_cve',
                pkg: pkgName,
                ver,
                cveId,
                severity,
                cweIds: (cweIds ?? []).join(', '),
                reason,
              },
              this.logger,
            );
          } else {
            if (
              !delta.vulnerableVersions ||
              !versionSatisfies(ver, delta.vulnerableVersions) ||
              !this._malPassesConfidenceFilters(delta)
            )
              continue;
            const reason =
              `SECURITY ALERT: ${pkgName}@${ver}, already cached in this registry, now matches known-` +
              `malicious-package advisory (${delta.malIds.join(', ')}) from OSV.`;
            this.logger.fatal(
              {pkg: pkgName, ver, malIds: delta.malIds},
              'security-filter: !!! CACHED PACKAGE NOW FLAGGED !!! @{pkg}@@{ver} matches known-malicious-' +
                'package advisory [@{malIds}] (OSV) -- already in local storage',
            );
            sendWebhook(
              this.webhookConfig,
              {
                event: 'osv_retroactive_mal',
                pkg: pkgName,
                ver,
                malIds: delta.malIds.join(', '),
                reason,
              },
              this.logger,
            );
          }
        }
      },
    });
  }

  // Conservative/safe-not-precise by design: if the withdrawn advisory was
  // one of several contributing to a package's entry, just drop that one id
  // (or cves[] entry) and leave the rest as-is (may over-block briefly)
  // rather than re-deriving an exact union from the remaining advisories.
  // Handles either a withdrawn MAL id or a withdrawn GHSA id, generically,
  // since a package's item can carry either or both dimensions.
  async _handleWithdrawal(id) {
    const isMal = osvClient.isMalRecord(id);
    for (const [pkgName, entry] of this._blocklist) {
      if (isMal) {
        if (!entry.malIds?.includes(id)) continue;
        const remainingIds = entry.malIds.filter(malId => malId !== id);
        if (remainingIds.length > 0) {
          entry.malIds = remainingIds;
        } else {
          delete entry.vulnerableVersions;
          delete entry.malIds;
          delete entry.originCount;
          delete entry.sources;
        }
      } else {
        if (!entry.cves?.some(c => c.id === id)) continue;
        const remainingCves = entry.cves.filter(c => c.id !== id);
        if (remainingCves.length > 0) {
          entry.cves = remainingCves;
        } else {
          delete entry.cves;
        }
      }

      if (entry.malIds === undefined && entry.cves === undefined) {
        await this.store.deleteItem(pkgName);
        this._blocklist.delete(pkgName);
        this.logger.info(
          {pkg: pkgName, id},
          'security-filter: osv -- advisory withdrawn, @{pkg} removed from blocklist',
        );
      } else {
        const item = {
          pk: pkgName,
          ...entry,
          modified: new Date().toISOString(),
        };
        await this.store.putItem(item);
        this.logger.info(
          {pkg: pkgName, id},
          'security-filter: osv -- advisory withdrawn, removed from @{pkg} (other advisories remain)',
        );
      }
    }
  }

  // Copies every dimension an item may carry (MAL fields, CVE entries, or
  // both) into the in-memory Map -- `pk` and `modified` are excluded, since
  // `pk` is the Map key itself and `modified` is pure bookkeeping check()
  // never consults.
  _applyToMemory(item) {
    const entry = {};
    if (item.vulnerableVersions !== undefined)
      entry.vulnerableVersions = item.vulnerableVersions;
    if (item.malIds !== undefined) entry.malIds = item.malIds;
    if (item.originCount !== undefined) entry.originCount = item.originCount;
    if (item.sources !== undefined) entry.sources = item.sources;
    if (item.cves !== undefined) entry.cves = item.cves;
    this._blocklist.set(item.pk, entry);
  }

  async _writeSyncState() {
    await this.store.putItem({
      pk: SYNC_STATE_KEY,
      lastSyncedModifiedId: this._lastSyncedModifiedId,
      csvEtag: this._csvEtag,
      csvLastModified: this._csvLastModified,
      bootstrapCompletedAt: this._bootstrapCompletedAt,
      extractionSchemaVersion: osvClient.EXTRACTION_SCHEMA_VERSION,
      updatedAt: new Date().toISOString(),
    });
  }

  close() {
    if (this._timer) clearTimeout(this._timer);
    this.store?.close()?.catch(() => {});
  }
}

let sharedStore = null;

function getAdvisoryStore(config, options) {
  if (!sharedStore) sharedStore = new MaliciousPackageStore(config, options);
  return sharedStore;
}

// Test-only: drop the module-level singleton so each test run starts clean.
function _resetSharedStoreForTests() {
  if (sharedStore) sharedStore.close();
  sharedStore = null;
}

module.exports = {
  getAdvisoryStore,
  MaliciousPackageStore,
  versionSatisfies,
  _resetSharedStoreForTests,
};
