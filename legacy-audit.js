'use strict';

// Serves the older /-/npm/v1/security/audits(/quick) protocol -- used by
// npm 6 and below (no concept of advisories/bulk at all, confirmed directly
// against npm 6's own lib/audit.js and lib/install/audit.js) and by yarn
// 2.x/3.x's own `yarn npm audit` (confirmed directly against real 2.4.3/
// 3.8.7 bundles: both call POST /-/npm/v1/security/audits/quick, never
// bulk). Unlike advisories/bulk, the client submits its OWN full dependency
// tree/graph in the request body -- this module has to walk that submitted
// tree itself to find every occurrence of a flagged package, since there's
// no simple {name: [versions]} payload to look up.
//
// Both real submission shapes -- npm 6's shrinkwrap-derived tree (lib/
// shrinkwrap.js's treeToShrinkwrap()) and yarn Berry's flat requires-graph
// (confirmed directly against yarn 3.8.7's own bundle) -- reduce to the
// same shape at every level: {requires: {name: rangeSelector}, dependencies:
// {name: {version, requires?, dependencies?, dev?}}}. npm 6's nested
// `dependencies` only appears for de-duplication-conflict copies (a
// different version of the same name required deeper in the tree); yarn's
// `dependencies` is always a single flat top-level map. One scope-chain
// walk (innermost-nested-dependencies-shadow-outer, same resolution order
// node_modules itself uses) handles both without needing to know which
// client sent it.

const {versionSatisfies} = require('./malicious-packages');

const KNOWN_SEVERITIES = new Set([
  'info',
  'low',
  'moderate',
  'high',
  'critical',
]);

// Bounds the walk on pathological/circular submitted graphs -- real
// dependency trees are nowhere near this deep, so this never fires in
// practice, it's just a backstop.
const MAX_DEPTH = 40;

// Shared with advisories/bulk's response shape (id/title/url/severity/
// vulnerable_versions/cwe/cvss) -- see its own comment for why those fields
// are built the way they are. module_name/patched_versions/findings are
// additions specific to this older protocol's own reporters.
function cveToNpmAdvisory(packageName, cve) {
  const label = cve.cveId ?? cve.id;
  return {
    id: cve.id,
    title: `${label} in ${packageName}`,
    url: `https://osv.dev/vulnerability/${cve.id}`,
    severity: cve.severity ?? undefined,
    vulnerable_versions: cve.vulnerableVersions,
    cwe: cve.cweIds?.length ? cve.cweIds : undefined,
    cvss:
      cve.cvss3Score != null
        ? {score: cve.cvss3Score}
        : cve.cvss4Score != null
          ? {score: cve.cvss4Score}
          : undefined,
  };
}

// `findings` groups every path a given (package, advisory) pair was found
// at by the exact installed version -- both npm's detail.js and yarn's own
// audit tree renderer read this shape directly.
function buildLegacyAdvisory(packageName, cve, occurrences) {
  const pathsByVersion = new Map();
  for (const {version, path} of occurrences) {
    if (!pathsByVersion.has(version)) pathsByVersion.set(version, new Set());
    pathsByVersion.get(version).add(path);
  }
  return {
    ...cveToNpmAdvisory(packageName, cve),
    module_name: packageName,
    // vulnerableVersions is deliberately a single OR'd semver clause, not a
    // first-patched-version (see osv-client.js) -- there's no reliable
    // upgrade target to recommend, so there's nothing honest to put here
    // beyond npm-audit-report's own "no patch available" sentinel (see its
    // detail.js reporter, which special-cases this exact string).
    patched_versions: '<0.0.0',
    // yarn Berry's own audit tree renderer reads this unconditionally --
    // confirmed directly against real 2.4.3/3.8.7 bundles: 2.4.3 calls
    // `.replace()` on it with no null-check at all (crashes outright if
    // missing), 3.8.7 null-checks but still fails a strict string-type
    // assertion on the resulting undefined. npm's own reporters never read
    // this field, so it's harmless there.
    recommendation:
      'No automated fix is available -- review this advisory manually.',
    findings: Array.from(pathsByVersion, ([version, paths]) => ({
      version,
      paths: Array.from(paths),
    })),
  };
}

function resolveInChain(scopeChain, name) {
  for (let i = scopeChain.length - 1; i >= 0; i--) {
    const info = scopeChain[i][name];
    if (info) return info;
  }
  return null;
}

// Walks the submitted tree/graph from every top-level dependency, recording
// every (package, version, path) occurrence actually reachable -- then
// checks each one against the real, unfiltered CVE store (getCveAdvisories,
// same source advisories/bulk uses) exactly the way a real install would.
function findVulnerableOccurrences(
  dependencies,
  topLevelNames,
  maliciousPackageStore,
) {
  const hitsByPackage = new Map(); // name -> Map(cveId -> {cve, occurrences: [{version, path, dev}]})
  const visitedPaths = new Set(); // bounds revisits on graphs with shared subtrees

  function recordHit(name, version, dev, path) {
    const cves = maliciousPackageStore?.getCveAdvisories(name) ?? [];
    for (const cve of cves) {
      if (
        !cve.vulnerableVersions ||
        !versionSatisfies(version, cve.vulnerableVersions)
      )
        continue;
      if (!hitsByPackage.has(name)) hitsByPackage.set(name, new Map());
      const byCve = hitsByPackage.get(name);
      if (!byCve.has(cve.id)) byCve.set(cve.id, {cve, occurrences: []});
      byCve.get(cve.id).occurrences.push({version, dev, path});
    }
  }

  function visit(name, ancestorNames, scopeChain) {
    const info = resolveInChain(scopeChain, name);
    if (!info || typeof info !== 'object') return;

    const path = [...ancestorNames, name].join('>');
    if (visitedPaths.has(path)) return;
    visitedPaths.add(path);

    if (info.version) recordHit(name, info.version, !!info.dev, path);

    if (ancestorNames.length >= MAX_DEPTH) return;
    const requires =
      info.requires && typeof info.requires === 'object' ? info.requires : null;
    if (!requires) return;
    const nextChain =
      info.dependencies && typeof info.dependencies === 'object'
        ? [...scopeChain, info.dependencies]
        : scopeChain;
    const nextAncestors = [...ancestorNames, name];
    for (const childName of Object.keys(requires)) {
      if (nextAncestors.includes(childName)) continue; // cycle guard
      visit(childName, nextAncestors, nextChain);
    }
  }

  for (const name of topLevelNames) {
    visit(name, [], [dependencies]);
  }

  return hitsByPackage;
}

// Shared by both /-/npm/v1/security/audits and /-/npm/v1/security/audits/
// quick -- the only difference upstream is that npm's plain-text "detail"
// reporter for the full /audits route additionally reads `actions` to
// render its human-readable per-package table (install.js's reporter for
// /quick never looks at it), so both routes just get the same full report.
// Every action is 'review', never 'update'/'install': see
// buildLegacyAdvisory()'s patched_versions comment for why there's no
// upgrade target to recommend automatically.
function buildLegacyAuditReport(body, maliciousPackageStore) {
  const dependencies =
    body?.dependencies && typeof body.dependencies === 'object'
      ? body.dependencies
      : {};
  // Both real shapes put EVERY resolved package -- direct and transitive
  // alike -- as a flat top-level entry in `dependencies` (confirmed
  // directly: npm 6's own shrinkwrapDeps() walks the whole tree.children
  // recursively into one flat map; yarn's tge() does the same over its
  // entire storedPackages graph). Only `requires` at the root actually
  // marks a package as a direct/top-level dependency of the project --
  // using dependencies' own keys as walk roots would treat every
  // transitive package as an extra fake root of its own, on top of
  // whatever real path already reaches it.
  const topLevelNames =
    body?.requires && typeof body.requires === 'object'
      ? Object.keys(body.requires)
      : Object.keys(dependencies); // malformed/missing requires: degrade to over-inclusive rather than blind

  const hitsByPackage = findVulnerableOccurrences(
    dependencies,
    topLevelNames,
    maliciousPackageStore,
  );

  const advisories = {};
  const vulnerabilities = {info: 0, low: 0, moderate: 0, high: 0, critical: 0};
  const actions = [];

  for (const [packageName, byCve] of hitsByPackage) {
    const resolves = [];
    for (const [cveId, {cve, occurrences}] of byCve) {
      advisories[cveId] = buildLegacyAdvisory(packageName, cve, occurrences);
      const severity = KNOWN_SEVERITIES.has(cve.severity)
        ? cve.severity
        : 'high';
      for (const occurrence of occurrences) {
        vulnerabilities[severity] += 1;
        resolves.push({id: cveId, path: occurrence.path, dev: occurrence.dev});
      }
    }
    actions.push({action: 'review', module: packageName, resolves});
  }

  return {
    advisories,
    metadata: {
      vulnerabilities,
      totalDependencies: Object.keys(dependencies).length,
    },
    actions,
  };
}

module.exports = {
  cveToNpmAdvisory,
  buildLegacyAuditReport,
};
