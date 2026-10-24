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

// Paths kept per (package, advisory) finding. The count of findings is
// what reporters show; past this many, more paths add nothing to read.
const MAX_PATHS_PER_FINDING = 100;

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
// (package, version, path) occurrences -- then checks each one against the
// real CVE store (getCveAdvisories, same source advisories/bulk uses -- both
// require the occurrence's own actual version(s) and filter by them, so
// neither can report a CVE whose vulnerableVersions range doesn't actually
// cover what's installed) exactly the way a real install would.
//
// Each (name, version) node has its own requires walked once, however many
// paths reach it: a graph where every package requires every other has a
// number of distinct paths exponential in its size, and enumerating them
// is how a 2 KB request used to occupy the event loop for seconds. Every
// edge into a node still records an occurrence (up to
// MAX_PATHS_PER_FINDING per finding), so reporters see each place a
// vulnerable package is required from. `maxVisits` caps the edges walked;
// past it the walk throws AUDIT_VISIT_BUDGET rather than return a report
// built from part of the graph.
function findVulnerableOccurrences(
  dependencies,
  topLevelNames,
  maliciousPackageStore,
  {maxVisits = Infinity, budget} = {},
) {
  const hitsByPackage = new Map(); // name -> Map(cveId -> {cve, occurrences: [{version, path, dev}]})
  const walked = new Set(); // name@version nodes whose requires were already walked
  const cvesByNode = new Map(); // name@version -> advisories, looked up once
  let visits = 0;

  function recordHit(name, version, dev, path) {
    const node = `${name}@${version}`;
    let cves = cvesByNode.get(node);
    if (cves === undefined) {
      cves =
        maliciousPackageStore?.getCveAdvisories(name, [version], budget) ?? [];
      cvesByNode.set(node, cves);
    }
    for (const cve of cves) {
      if (!hitsByPackage.has(name)) hitsByPackage.set(name, new Map());
      const byCve = hitsByPackage.get(name);
      if (!byCve.has(cve.id)) byCve.set(cve.id, {cve, occurrences: []});
      const {occurrences} = byCve.get(cve.id);
      if (occurrences.length < MAX_PATHS_PER_FINDING) {
        occurrences.push({version, dev, path});
      }
    }
  }

  function visit(name, ancestorNames, scopeChain) {
    visits += 1;
    if (visits > maxVisits) {
      throw Object.assign(
        new Error(`audit graph walk passed ${maxVisits} edges`),
        {code: 'AUDIT_VISIT_BUDGET'},
      );
    }
    const info = resolveInChain(scopeChain, name);
    if (!info || typeof info !== 'object') return;

    const version = typeof info.version === 'string' ? info.version : null;
    const path = [...ancestorNames, name].join('>');
    if (version) recordHit(name, version, !!info.dev, path);

    // A node reached at the depth cap isn't marked walked: a shorter path
    // may reach it later, and that one walks its requires.
    if (ancestorNames.length >= MAX_DEPTH) return;
    const node = `${name}@${version ?? ''}`;
    if (walked.has(node)) return;
    walked.add(node);

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
function buildLegacyAuditReport(body, maliciousPackageStore, limits) {
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
    limits,
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
