'use strict';

// Pure OSV (https://osv.dev) wire-format concerns for the npm ecosystem's
// feed -- no AWS/DynamoDB knowledge lives here, only HTTP fetch plus zip/CSV
// parsing and extracting the minimal fields this plugin ever keeps. Two
// record types are relevant: `MAL-` (confirmed-malicious packages) and
// `GHSA-` (real CVE-backed vulnerabilities) -- everything else (`GSD-`,
// etc.) is ignored. A full raw OSV record (summary/details/credits
// included) is never retained past the single extraction step in this file
// -- see docs/plugins/security-filter.md's "Cost characteristics" section
// for why that matters at ~220k current entries.

const semver = require('semver');
const yauzl = require('yauzl');
const {Cvss3P1, Cvss4P0} = require('ae-cvss-calculator');

const MAL_ID_PREFIX = 'MAL-';
const CVE_ID_PREFIX = 'GHSA-';

// Bump this whenever a change to the extraction logic in this file means
// data an older version already wrote to storage is stale/incomplete in a
// way the sync loop's own modified_id.csv watermark can never detect on its
// own (that watermark only tracks whether OSV's *data* changed, not whether
// this plugin's own interpretation of it did). malicious-packages.js
// compares this against what's stored in SYNC_STATE_KEY at warm-start and
// forces a full re-bootstrap on any mismatch, rather than waiting for each
// individual advisory to happen to receive a fresh OSV-side update.
const EXTRACTION_SCHEMA_VERSION = 2;

function isMalRecord(id) {
  return typeof id === 'string' && id.startsWith(MAL_ID_PREFIX);
}

function isCveRecord(id) {
  return typeof id === 'string' && id.startsWith(CVE_ID_PREFIX);
}

// Normalizes one affected[] entry's ranges[].events into {introduced, fixed,
// lastAffected} triples. "0" is OSV's own sentinel for "no lower bound" --
// preserved as-is and interpreted later by malicious-packages.js's version
// matcher, so both the bootstrap and incremental paths share one meaning
// for it.
//
// `fixed` and `lastAffected` are kept as two separate fields, not one,
// because the OSV schema defines them with different upper-bound semantics
// (https://ossf.github.io/osv-schema/): `fixed` is exclusive (versions >=
// fixed are safe), `last_affected` is inclusive ("versions above
// last_affected should be considered unaffected"). The schema also
// guarantees a range's events never contain both -- "can contain either
// last_affected or fixed events, but not both" -- so exactly one of these
// two fields (or neither, for a still-open/unfixed range) is ever set per
// range; there's no conflict to resolve between them.
// GitHub's own free-text escape hatch for a fix boundary the OSV events[]
// structure has no field for at all -- carried at the per-affected-entry
// level as database_specific.last_known_affected_version_range (NOT part of
// the core OSV schema; GitHub's own docs say database_specific "is not
// intended to influence vulnerability evaluation," so this is only ever
// consulted as a last resort, never in preference to a real structured
// event). Best-effort, on purpose: only the two single-clause forms
// actually observed in the wild ("< X", "<= X") are parsed; anything else
// -- multiple clauses, other operators, garbage -- returns null and leaves
// the range open/unbounded, exactly like today's fail-closed handling of
// any other unparseable bound.
function parseLastKnownAffectedVersionRange(raw) {
  if (typeof raw !== 'string') return null;
  const m = raw.trim().match(/^(<=|<)\s*(\S+)$/);
  if (!m) return null;
  const [, operator, version] = m;
  return operator === '<=' ? {lastAffected: version} : {fixed: version};
}

function normalizeRanges(affectedEntry) {
  const ranges = [];
  for (const range of affectedEntry.ranges ?? []) {
    if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;
    let introduced = '0';
    let fixed = null;
    let lastAffected = null;
    for (const event of range.events ?? []) {
      if (event.introduced !== undefined) introduced = event.introduced;
      if (event.fixed !== undefined) fixed = event.fixed;
      if (event.last_affected !== undefined) lastAffected = event.last_affected;
    }
    if (fixed == null && lastAffected == null) {
      const fallback = parseLastKnownAffectedVersionRange(
        affectedEntry.database_specific?.last_known_affected_version_range,
      );
      if (fallback) {
        fixed = fallback.fixed ?? null;
        lastAffected = fallback.lastAffected ?? null;
      }
    }
    ranges.push({introduced, fixed, lastAffected});
  }
  return ranges;
}

// Converts one {introduced, fixed, lastAffected} triple into a real semver
// range clause -- the ONLY place this conversion ever happens (once, at
// import), so both this plugin's own matching (malicious-packages.js's
// versionSatisfies(), a plain semver.satisfies() call) and the real
// advisories/bulk client-facing response read the exact same precomputed
// string. Replicates versionMatchesRanges()'s prior fail-closed semantics
// exactly: an unparseable bound is OMITTED (never embedded as a literal
// invalid range clause, which semver.satisfies() would just choke on) --
// an unparseable `introduced` means no lower bound (matches from the very
// start, same as the "0" sentinel), an unparseable `fixed`/`lastAffected`
// means no upper bound (matches forever above `introduced`, same as a
// still-open/unfixed range with neither field set).
function rangeToSemverClause({introduced, fixed, lastAffected}) {
  const parts = [];
  const lower =
    introduced === '0'
      ? null
      : (semver.valid(introduced) ?? semver.valid(semver.coerce(introduced)));
  if (lower != null) parts.push(`>=${lower}`);

  if (fixed != null) {
    const upper = semver.valid(fixed) ?? semver.valid(semver.coerce(fixed));
    if (upper != null) parts.push(`<${upper}`);
  } else if (lastAffected != null) {
    const upper =
      semver.valid(lastAffected) ?? semver.valid(semver.coerce(lastAffected));
    if (upper != null) parts.push(`<=${upper}`);
  }

  return parts.length > 0 ? parts.join(' ') : '*';
}

// Folds both a range triples array AND an explicit exact-versions list
// (OSV's affected[].versions -- a bare version string is already a valid,
// single-version semver range on its own) into ONE OR-joined semver range
// string -- the single stored/matched-against/served representation for a
// package's affected versions, replacing what used to be two separate
// fields (`ranges` and `versions`) checked independently. Returns null only
// if given nothing at all; every caller here already filters that case out
// before calling this.
function toVulnerableVersions(ranges, versions = []) {
  const clauses = [...ranges.map(rangeToSemverClause), ...versions];
  return clauses.length > 0 ? clauses.join(' || ') : null;
}

// Independent corroborating detectors that flagged a MAL- package (source +
// advisory id + timestamps) -- only `source`, deduplicated, and the count
// are ever kept; the rest (timestamps, per-origin sha256/ranges) is exactly
// the kind of extra detail this file exists to discard.
function extractOrigins(raw) {
  const origins = raw.database_specific?.['malicious-packages-origins'] ?? [];
  return {
    originCount: origins.length,
    sources: Array.from(new Set(origins.map(o => o.source).filter(Boolean))),
  };
}

function extractMalRecord(raw) {
  // Withdrawn records carry no packages -- callers that care (incremental
  // sync) act on the withdrawal itself; bootstrap simply skips them, since
  // there's nothing yet to withdraw when building the table from scratch.
  if (raw.withdrawn) return {id: raw.id, withdrawn: true};

  const byPackage = new Map();
  for (const entry of raw.affected ?? []) {
    if (entry.package?.ecosystem !== 'npm' || !entry.package?.name) continue;
    const ranges = normalizeRanges(entry);
    if (ranges.length === 0) continue;
    const existing = byPackage.get(entry.package.name) ?? [];
    byPackage.set(entry.package.name, existing.concat(ranges));
  }
  if (byPackage.size === 0) return null;

  const {originCount, sources} = extractOrigins(raw);

  return {
    id: raw.id,
    modified: raw.modified,
    packages: Array.from(byPackage, ([name, ranges]) => ({
      name,
      vulnerableVersions: toVulnerableVersions(ranges),
      originCount,
      sources,
    })),
  };
}

// Computes the CVSS base score for each version actually present on the
// record's top-level severity[] array (real npm GHSA data only ever
// carries CVSS_V3 -- specifically 3.1, never 3.0 -- and/or CVSS_V4;
// verified directly against a 220-record live sample, no V2 observed).
// Kept as two independent fields, not collapsed into one -- osv.cve.cvss3/
// osv.cve.cwe4 filter on each separately, mirroring how severity/cwe are
// each their own dimension. A missing or unparseable vector for a given
// version just leaves that field null; it never blocks the other version's
// score or falls back to it.
function computeCvssScores(raw) {
  let cvss3Score = null;
  let cvss4Score = null;
  for (const entry of raw.severity ?? []) {
    try {
      if (entry.type === 'CVSS_V3' && cvss3Score == null) {
        cvss3Score = new Cvss3P1(entry.score).calculateScores().base;
      } else if (entry.type === 'CVSS_V4' && cvss4Score == null) {
        cvss4Score = new Cvss4P0(entry.score).calculateScores().base;
      }
    } catch {
      // Malformed/unsupported vector string -- leave that score null rather
      // than let one bad entry abort extraction of the rest of the record.
    }
  }
  return {cvss3Score, cvss4Score};
}

// GHSA (real CVE-backed) records use the same affected[]/ranges[] shape as
// MAL, but ~840 npm records across the feed instead give an explicit
// affected[].versions list -- both forms are kept (as parallel `ranges`/
// `versions` arrays, either of which may be empty) since a single record
// can mix both across different affected[] entries.
function extractCveRecord(raw) {
  if (raw.withdrawn) return {id: raw.id, withdrawn: true};

  const byPackage = new Map();
  for (const entry of raw.affected ?? []) {
    if (entry.package?.ecosystem !== 'npm' || !entry.package?.name) continue;
    const ranges = normalizeRanges(entry);
    const versions = Array.isArray(entry.versions) ? entry.versions : [];
    if (ranges.length === 0 && versions.length === 0) continue;
    const existing = byPackage.get(entry.package.name) ?? {
      ranges: [],
      versions: [],
    };
    existing.ranges = existing.ranges.concat(ranges);
    existing.versions = existing.versions.concat(versions);
    byPackage.set(entry.package.name, existing);
  }
  if (byPackage.size === 0) return null;

  // First CVE- alias, kept only for forensic logging -- not filtered on,
  // since severity/CWE (below) are what's actually configurable.
  const cveId =
    (raw.aliases ?? []).find(
      a => typeof a === 'string' && a.startsWith('CVE-'),
    ) ?? null;

  const {cvss3Score, cvss4Score} = computeCvssScores(raw);

  return {
    id: raw.id,
    modified: raw.modified,
    cveId,
    // Lowercased here, at the source -- OSV's own bucket is uppercase
    // (LOW/MODERATE/HIGH/CRITICAL), but lowercase is this plugin's
    // canonical internal form (matches npm/yarn's audit wire format; see
    // malicious-packages.js's KNOWN_SEVERITIES). Every consumer of
    // extracted CVE data gets the normalized form for free -- there's no
    // second place that still expects uppercase.
    severity: raw.database_specific?.severity?.toLowerCase() ?? null,
    cweIds: raw.database_specific?.cwe_ids ?? [],
    cvss3Score,
    cvss4Score,
    packages: Array.from(byPackage, ([name, {ranges, versions}]) => ({
      name,
      vulnerableVersions: toVulnerableVersions(ranges, versions),
    })),
  };
}

// Extracts the minimal fields this plugin ever keeps from one raw OSV
// record. Returns null for anything not relevant (neither MAL- nor GHSA-,
// or a record with no usable npm-ecosystem range/version) so callers can
// filter with a simple truthy check.
function extractMinimalRecord(raw) {
  if (!raw) return null;
  if (isMalRecord(raw.id)) return extractMalRecord(raw);
  if (isCveRecord(raw.id)) return extractCveRecord(raw);
  return null;
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {...options, signal: controller.signal});
  } finally {
    clearTimeout(timer);
  }
}

function readEntryAsJson(zipfile, entry) {
  return new Promise((resolve, reject) => {
    zipfile.openReadStream(entry, (err, stream) => {
      if (err) return reject(err);
      const chunks = [];
      stream.on('data', c => chunks.push(c));
      stream.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch (parseErr) {
          reject(parseErr);
        }
      });
      stream.on('error', reject);
    });
  });
}

// Called once per entry across the whole zip (~207k times for the current
// npm feed) -- each call's 'entry'/'end'/'error' .once() listeners only
// self-remove on the branch that actually fires, so the other two would
// otherwise accumulate as dead listeners on the shared zipfile for the
// entire walk (surfaced as a real MaxListenersExceededWarning against the
// live feed, invisible against the tiny fixture zips test/smoke-* uses).
// Explicit cleanup() removes whichever ones didn't fire.
function nextZipEntry(zipfile) {
  return new Promise((resolve, reject) => {
    function cleanup() {
      zipfile.off('entry', onEntry);
      zipfile.off('end', onEnd);
      zipfile.off('error', onError);
    }
    function onEntry(entry) {
      cleanup();
      resolve(entry);
    }
    function onEnd() {
      cleanup();
      resolve(null);
    }
    function onError(err) {
      cleanup();
      reject(err);
    }
    zipfile.once('entry', onEntry);
    zipfile.once('end', onEnd);
    zipfile.once('error', onError);
    zipfile.readEntry();
  });
}

// Downloads npm/all.zip in full (a one-time, per-bootstrap cost) and yields
// one minimal record at a time. Only one full raw OSV record is ever parsed
// into memory at once -- it's extracted down to ~100 bytes and discarded
// before the next entry is read, regardless of how large the zip is overall.
async function* fetchAllRecords({baseUrl, timeoutMs, logger}) {
  const res = await fetchWithTimeout(
    new URL('all.zip', baseUrl),
    {},
    timeoutMs,
  );
  if (!res.ok)
    throw new Error(`osv: fetching all.zip failed: HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());

  const zipfile = await new Promise((resolve, reject) => {
    yauzl.fromBuffer(buf, {lazyEntries: true}, (err, zf) =>
      err ? reject(err) : resolve(zf),
    );
  });

  try {
    for (
      let entry = await nextZipEntry(zipfile);
      entry;
      entry = await nextZipEntry(zipfile)
    ) {
      if (/\/$/.test(entry.fileName)) continue; // directory entry, nothing to read

      let minimal = null;
      try {
        minimal = extractMinimalRecord(await readEntryAsJson(zipfile, entry));
      } catch (err) {
        logger?.warn(
          {file: entry.fileName, err: err.message},
          'security-filter: osv -- skipping unparseable record',
        );
      }
      if (minimal) yield minimal;
    }
  } finally {
    zipfile.close();
  }
}

// Conditional GET against npm/modified_id.csv using the caller's
// previously-stored ETag/Last-Modified. Returns {notModified: true} on a
// 304 (the expected common case every poll cycle) without parsing anything
// further, or {rows, etag, lastModified} on a 200. Rows are `modified,id`
// pairs (verified against the live feed) emitted newest-first, so when the
// caller passes `sinceModified` (the last high-water-mark it already
// processed), parsing stops as soon as it reaches that mark instead of
// walking the rest of an ~8MB file for rows already known to be processed.
async function fetchModifiedCsv({
  baseUrl,
  etag,
  lastModified,
  sinceModified,
  timeoutMs,
}) {
  const headers = {};
  if (etag) headers['If-None-Match'] = etag;
  if (lastModified) headers['If-Modified-Since'] = lastModified;

  const res = await fetchWithTimeout(
    new URL('modified_id.csv', baseUrl),
    {headers},
    timeoutMs,
  );
  if (res.status === 304) return {notModified: true};
  if (!res.ok)
    throw new Error(`osv: fetching modified_id.csv failed: HTTP ${res.status}`);

  const text = await res.text();
  const rows = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const commaIndex = trimmed.indexOf(',');
    if (commaIndex === -1) continue;
    const modified = trimmed.slice(0, commaIndex);
    const id = trimmed.slice(commaIndex + 1);
    // ISO-8601 strings sort lexicographically the same as chronologically,
    // so a plain string comparison is enough -- no Date parsing needed.
    if (sinceModified && modified <= sinceModified) break;
    rows.push({modified, id});
  }

  return {
    rows,
    etag: res.headers.get('etag'),
    lastModified: res.headers.get('last-modified'),
  };
}

// Fetches and extracts a single changed/new record by id (npm/<ID>.json).
async function fetchRecord(id, {baseUrl, timeoutMs}) {
  const res = await fetchWithTimeout(
    new URL(`${id}.json`, baseUrl),
    {},
    timeoutMs,
  );
  if (!res.ok)
    throw new Error(`osv: fetching ${id}.json failed: HTTP ${res.status}`);
  return extractMinimalRecord(await res.json());
}

module.exports = {
  isMalRecord,
  isCveRecord,
  fetchAllRecords,
  fetchModifiedCsv,
  fetchRecord,
  EXTRACTION_SCHEMA_VERSION,
};
