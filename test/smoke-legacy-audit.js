'use strict';

// Manual smoke test for legacy-audit.js -- no framework, matching this
// repo's house style (see test/smoke.js). Exercises buildLegacyAuditReport()
// directly against synthetic request bodies shaped like npm 6's own
// shrinkwrap-derived tree (nested `dependencies` for de-dup conflicts) and
// yarn Berry's own flat requires-graph -- both real shapes, confirmed
// directly against each client's own source (see legacy-audit.js's own
// top-of-file comment). Run with:
//   node verdaccio-security-filter/test/smoke-legacy-audit.js

const assert = require('node:assert/strict');
const {buildLegacyAuditReport} = require('../legacy-audit.js');

function fakeStore(cvesByPackage) {
  return {
    getCveAdvisories(name) {
      return cvesByPackage[name] ?? [];
    },
  };
}

function cve(overrides = {}) {
  return {
    id: 'GHSA-test-0000',
    cveId: 'CVE-2024-0001',
    severity: 'high',
    cweIds: ['CWE-1321'],
    cvss3Score: 7.5,
    cvss4Score: null,
    vulnerableVersions: '*',
    ...overrides,
  };
}

async function main() {
  let passed = 0;

  async function check(name, fn) {
    try {
      await fn();
      passed++;
      console.log(`PASS: ${name}`);
    } catch (err) {
      console.error(`FAIL: ${name}`);
      console.error(err);
      process.exitCode = 1;
    }
  }

  await check(
    'no dependencies at all yields an honest empty report, not a crash',
    () => {
      const report = buildLegacyAuditReport({}, fakeStore({}));
      assert.deepEqual(report, {
        advisories: {},
        metadata: {
          vulnerabilities: {info: 0, low: 0, moderate: 0, high: 0, critical: 0},
          totalDependencies: 0,
        },
        actions: [],
      });
    },
  );

  await check(
    'a non-object body (undefined store lookups, malformed JSON) never crashes',
    () => {
      const report = buildLegacyAuditReport(null, fakeStore({}));
      assert.equal(Object.keys(report.advisories).length, 0);
      assert.equal(report.metadata.totalDependencies, 0);
    },
  );

  await check(
    'npm 6 shape: a flat top-level dependency with a real seeded advisory is found',
    () => {
      const body = {
        requires: {'evil-pkg': '^1.0.0'},
        dependencies: {
          'evil-pkg': {version: '1.0.0', requires: {}},
        },
      };
      const report = buildLegacyAuditReport(
        body,
        fakeStore({'evil-pkg': [cve()]}),
      );
      assert.equal(Object.keys(report.advisories).length, 1);
      const advisory = report.advisories['GHSA-test-0000'];
      assert.equal(advisory.module_name, 'evil-pkg');
      assert.equal(advisory.severity, 'high');
      assert.equal(advisory.patched_versions, '<0.0.0');
      // yarn Berry's own audit tree renderer reads this field unconditionally
      // (2.4.3 crashes outright without a null-check, 3.8.7 fails a strict
      // string-type assertion) -- confirmed directly against real bundles,
      // see legacy-audit.js's own comment on this field.
      assert.equal(typeof advisory.recommendation, 'string');
      assert.deepEqual(advisory.findings, [
        {version: '1.0.0', paths: ['evil-pkg']},
      ]);
      assert.equal(report.metadata.vulnerabilities.high, 1);
      assert.equal(report.metadata.totalDependencies, 1);
      assert.deepEqual(report.actions, [
        {
          action: 'review',
          module: 'evil-pkg',
          resolves: [{id: 'GHSA-test-0000', path: 'evil-pkg', dev: false}],
        },
      ]);
    },
  );

  await check(
    'npm 6 shape: a nested de-dup override resolves to the DEEPER version at that path',
    () => {
      // top-level "safe-pkg"@2.0.0 (clean) transitively requires "evil-pkg"
      // ^1.0.0, but a second top-level package needs evil-pkg@1.0.0
      // specifically -- classic npm shrinkwrap de-dup: the top-level
      // dependencies map gets the hoisted 2.0.0 copy, and a nested
      // dependencies map under the package that needed 1.0.0 shadows it for
      // that subtree only.
      const body = {
        requires: {'evil-pkg': '^2.0.0', consumer: '^1.0.0'},
        dependencies: {
          'evil-pkg': {version: '2.0.0'}, // hoisted copy: not vulnerable
          consumer: {
            version: '1.0.0',
            requires: {'evil-pkg': '^1.0.0'},
            dependencies: {
              'evil-pkg': {version: '1.0.0'}, // shadowed copy: vulnerable
            },
          },
        },
      };
      const report = buildLegacyAuditReport(
        body,
        fakeStore({'evil-pkg': [cve({vulnerableVersions: '<2.0.0'})]}),
      );
      const advisory = report.advisories['GHSA-test-0000'];
      // only the nested 1.0.0 occurrence is vulnerable -- the hoisted 2.0.0
      // top-level occurrence must NOT show up as a finding.
      assert.deepEqual(advisory.findings, [
        {version: '1.0.0', paths: ['consumer>evil-pkg']},
      ]);
      assert.equal(report.metadata.vulnerabilities.high, 1);
    },
  );

  await check(
    'yarn Berry shape: a flat requires-graph is walked to find a transitive occurrence',
    () => {
      // yarn's own shape never nests `dependencies` -- every package is a
      // top-level entry in one flat map, and the graph is reconstructed
      // purely by following each entry's own `requires` map.
      const body = {
        requires: {a: '^1.0.0'},
        dependencies: {
          a: {version: '1.0.0', requires: {b: '^2.0.0'}},
          b: {version: '2.0.0', requires: {}},
        },
      };
      const report = buildLegacyAuditReport(body, fakeStore({b: [cve()]}));
      const advisory = report.advisories['GHSA-test-0000'];
      assert.deepEqual(advisory.findings, [{version: '2.0.0', paths: ['a>b']}]);
      assert.equal(report.metadata.totalDependencies, 2);
    },
  );

  await check(
    'the same vulnerable package reached via two different paths aggregates both paths, counts twice',
    () => {
      const body = {
        requires: {a: '^1.0.0', c: '^1.0.0'},
        dependencies: {
          a: {version: '1.0.0', requires: {shared: '^1.0.0'}},
          c: {version: '1.0.0', requires: {shared: '^1.0.0'}},
          shared: {version: '1.0.0', requires: {}},
        },
      };
      const report = buildLegacyAuditReport(body, fakeStore({shared: [cve()]}));
      const advisory = report.advisories['GHSA-test-0000'];
      assert.deepEqual(advisory.findings, [
        {version: '1.0.0', paths: ['a>shared', 'c>shared']},
      ]);
      // one "vulnerability" per occurrence, not per distinct advisory --
      // matches real npm/yarn's own counting convention.
      assert.equal(report.metadata.vulnerabilities.high, 2);
      const action = report.actions.find(a => a.module === 'shared');
      assert.equal(action.resolves.length, 2);
    },
  );

  await check(
    'two distinct advisories on the same package both appear, grouped under one review action',
    () => {
      const body = {
        requires: {'evil-pkg': '^1.0.0'},
        dependencies: {'evil-pkg': {version: '1.0.0', requires: {}}},
      };
      const report = buildLegacyAuditReport(
        body,
        fakeStore({
          'evil-pkg': [
            cve({id: 'GHSA-aaaa', severity: 'high'}),
            cve({id: 'GHSA-bbbb', severity: 'critical'}),
          ],
        }),
      );
      assert.deepEqual(Object.keys(report.advisories).sort(), [
        'GHSA-aaaa',
        'GHSA-bbbb',
      ]);
      assert.equal(report.metadata.vulnerabilities.high, 1);
      assert.equal(report.metadata.vulnerabilities.critical, 1);
      assert.equal(report.actions.length, 1);
      assert.equal(report.actions[0].module, 'evil-pkg');
      assert.deepEqual(report.actions[0].resolves.map(r => r.id).sort(), [
        'GHSA-aaaa',
        'GHSA-bbbb',
      ]);
    },
  );

  await check('a version outside vulnerableVersions is never reported', () => {
    const body = {
      requires: {'fixed-pkg': '^2.0.0'},
      dependencies: {'fixed-pkg': {version: '2.5.0', requires: {}}},
    };
    const report = buildLegacyAuditReport(
      body,
      fakeStore({'fixed-pkg': [cve({vulnerableVersions: '<2.0.0'})]}),
    );
    assert.deepEqual(report.advisories, {});
    assert.equal(report.actions.length, 0);
  });

  await check(
    'dev: true on the submitted tree entry threads through to resolves[].dev',
    () => {
      const body = {
        requires: {'evil-pkg': '^1.0.0'},
        dependencies: {'evil-pkg': {version: '1.0.0', dev: true, requires: {}}},
      };
      const report = buildLegacyAuditReport(
        body,
        fakeStore({'evil-pkg': [cve()]}),
      );
      assert.equal(report.actions[0].resolves[0].dev, true);
    },
  );

  await check(
    'an unknown/missing severity falls back to high, same as advisories/bulk',
    () => {
      const body = {
        requires: {'evil-pkg': '^1.0.0'},
        dependencies: {'evil-pkg': {version: '1.0.0', requires: {}}},
      };
      const report = buildLegacyAuditReport(
        body,
        fakeStore({'evil-pkg': [cve({severity: undefined})]}),
      );
      assert.equal(report.metadata.vulnerabilities.high, 1);
    },
  );

  await check(
    'a circular requires graph terminates instead of hanging or crashing',
    () => {
      const body = {
        requires: {a: '^1.0.0'},
        dependencies: {
          a: {version: '1.0.0', requires: {b: '^1.0.0'}},
          b: {version: '1.0.0', requires: {a: '^1.0.0'}}, // cycle back to a
        },
      };
      const report = buildLegacyAuditReport(body, fakeStore({b: [cve()]}));
      const advisory = report.advisories['GHSA-test-0000'];
      assert.deepEqual(advisory.findings, [{version: '1.0.0', paths: ['a>b']}]);
    },
  );

  console.log(`\n${passed} check(s) passed.`);
}

main();
