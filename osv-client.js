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

const yauzl = require('yauzl');

const MAL_ID_PREFIX = 'MAL-';
const CVE_ID_PREFIX = 'GHSA-';

function isMalRecord(id) {
  return typeof id === 'string' && id.startsWith(MAL_ID_PREFIX);
}

function isCveRecord(id) {
  return typeof id === 'string' && id.startsWith(CVE_ID_PREFIX);
}

// Normalizes one affected[] entry's ranges[].events into {introduced, fixed}
// pairs. "0" is OSV's own sentinel for "no lower bound" -- preserved as-is
// and interpreted later by malicious-packages.js's version matcher, so both
// the bootstrap and incremental paths share one meaning for it.
function normalizeRanges(affectedEntry) {
  const ranges = [];
  for (const range of affectedEntry.ranges ?? []) {
    if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;
    let introduced = '0';
    let fixed = null;
    for (const event of range.events ?? []) {
      if (event.introduced !== undefined) introduced = event.introduced;
      if (event.fixed !== undefined) fixed = event.fixed;
    }
    ranges.push({introduced, fixed});
  }
  return ranges;
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
      ranges,
      originCount,
      sources,
    })),
  };
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

  return {
    id: raw.id,
    modified: raw.modified,
    cveId,
    severity: raw.database_specific?.severity ?? null,
    cweIds: raw.database_specific?.cwe_ids ?? [],
    packages: Array.from(byPackage, ([name, {ranges, versions}]) => ({
      name,
      ranges,
      versions,
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
};
