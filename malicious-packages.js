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
const KNOWN_SEVERITIES = new Set(['LOW', 'MODERATE', 'HIGH', 'CRITICAL']);

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

// A whole-package block is just a range of {introduced:"0", fixed:null} --
// no separate code path is needed for "whole package" vs "specific
// versions," this is the only matcher either case ever goes through.
// Unparseable bounds fail closed toward *more* blocking (an unparseable
// `fixed` doesn't exempt anything above it; an unparseable `introduced`
// doesn't exempt anything below it), matching this plugin's existing
// "unknown -> block" philosophy elsewhere (e.g. an unknown publish date).
function versionMatchesRanges(version, ranges) {
  const parsed = semver.valid(version) ?? semver.valid(semver.coerce(version));
  if (!parsed) return true; // can't parse the version of an already-flagged package -- fail closed

  return ranges.some(({introduced, fixed}) => {
    const lower =
      introduced === '0'
        ? null
        : (semver.valid(introduced) ?? semver.valid(semver.coerce(introduced)));
    const upper =
      fixed == null
        ? null
        : (semver.valid(fixed) ?? semver.valid(semver.coerce(fixed)));
    const lowerOk = lower == null || semver.gte(parsed, lower);
    const upperOk = upper == null || semver.lt(parsed, upper);
    return lowerOk && upperOk;
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

function parseCveSeverities(list, source) {
  for (const sev of list) {
    if (!KNOWN_SEVERITIES.has(sev)) {
      throw new Error(
        `security-filter: ${source} has unknown severity '${sev}' -- must be one of ${Array.from(KNOWN_SEVERITIES).join(', ')}`,
      );
    }
  }
  return list;
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
    parseCveSeverities(severities, `${source} entry for '${cweId}'`);
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

  // Hot path: zero network/storage calls, a plain Map lookup plus a small
  // semver comparison. This is what filter_metadata()/the publish gate call
  // on every single request. Checks the MAL dimension first (gated by
  // osv.malware.minOrigin/osv.malware.sources), then any CVE entries (gated
  // by osv.cve.severity/osv.cve.cwe) -- an entry can carry either, neither, or both.
  check(name, version) {
    const entry = this._blocklist.get(name);
    if (!entry) return null;

    if (
      entry.ranges &&
      versionMatchesRanges(version, entry.ranges) &&
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

  // A CVE can affect a version via a semver range or an explicit versions
  // list (or both, on records that mix the two forms across affected[]
  // entries) -- either is sufficient.
  _cveVersionAffected(version, cve) {
    if (cve.ranges?.length && versionMatchesRanges(version, cve.ranges))
      return true;
    if (cve.versions?.length && cve.versions.includes(version)) return true;
    return false;
  }

  // OR at the top level: the global severity gate, or a CWE-specific gate.
  // A bare osv.cve.cwe entry (empty severities array) matches at ANY
  // severity, overriding the global list for that CWE; a non-empty
  // severities array on a CWE entry replaces the global list for that CWE
  // rather than being combined with it.
  _cveMatchesFilters(cve) {
    if (this.cveSeverities.length === 0 && this.cweRules.size === 0)
      return false; // both disabled
    if (cve.severity && this.cveSeverities.includes(cve.severity)) return true;
    for (const cweId of cve.cweIds ?? []) {
      if (!this.cweRules.has(cweId)) continue;
      const severities = this.cweRules.get(cweId);
      if (severities.length === 0) return true; // bare -- any severity
      if (cve.severity && severities.includes(cve.severity)) return true;
    }
    return false;
  }

  // Full scan over the whole backend, run once at construction so a
  // freshly-started/newly-scaled pod doesn't have to wait for a full poll
  // cycle before OSV-based blocking is active.
  async _warmStart() {
    const items = await this.store.scanAll();
    for (const item of items) {
      if (item.pk === SYNC_STATE_KEY) {
        this._bootstrapCompletedAt = item.bootstrapCompletedAt ?? null;
        this._lastSyncedModifiedId = item.lastSyncedModifiedId ?? null;
        this._csvEtag = item.csvEtag ?? null;
        this._csvLastModified = item.csvLastModified ?? null;
      } else {
        this._applyToMemory(item);
      }
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
          this.logger.error(
            {err: err.message},
            'security-filter: osv -- sync cycle failed',
          ),
        )
        .finally(() => this._scheduleNext());
    }, delay);
    this._timer.unref?.(); // don't keep the process (or a test run) alive solely for this timer
  }

  async runSyncCycle() {
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
            item.ranges = pkg.ranges;
            item.malIds = [record.id];
            item.originCount = pkg.originCount;
            item.sources = pkg.sources;
          } else {
            item.cves = (item.cves ?? []).concat({
              id: record.id,
              cveId: record.cveId,
              severity: record.severity,
              cweIds: record.cweIds,
              ranges: pkg.ranges,
              versions: pkg.versions,
            });
          }
          item.modified = record.modified;
          staging.set(pkg.name, item);
        }
      }
    } catch (err) {
      this.logger.error(
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
      this.logger.error(
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
      this.logger.warn(
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
      this.logger.error(
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
                  ranges: pkg.ranges,
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
                    ranges: pkg.ranges,
                    versions: pkg.versions,
                  },
                },
          );
          if (!applied) {
            allApplied = false;
            continue;
          }
          this.logger.warn(
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
      merged.ranges = delta.ranges;
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
            this.logger.error(
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
              !versionMatchesRanges(ver, delta.ranges ?? []) ||
              !this._malPassesConfidenceFilters(delta)
            )
              continue;
            const reason =
              `SECURITY ALERT: ${pkgName}@${ver}, already cached in this registry, now matches known-` +
              `malicious-package advisory (${delta.malIds.join(', ')}) from OSV.`;
            this.logger.error(
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
          delete entry.ranges;
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
        this.logger.warn(
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
        this.logger.warn(
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
    if (item.ranges !== undefined) entry.ranges = item.ranges;
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
  versionMatchesRanges,
  _resetSharedStoreForTests,
};
