'use strict';

// Manual smoke test for the version-matching and OSV-range-conversion
// pipeline -- no framework, matching this repo's house style (see
// test/smoke.js). This file exists because a real production bug shipped
// through a gap exactly here: getCveAdvisories() (malicious-packages.js)
// used to return every CVE a package has EVER had regardless of which
// version is actually installed, so a live registry reported verdaccio
// itself as vulnerable to CVE-2019-14772 (vulnerableVersions "<3.12.0")
// while actually running verdaccio 6.7.4 -- a version nowhere near that
// range. Neither versionSatisfies() nor the OSV range-conversion functions
// in osv-client.js (normalizeRanges/rangeToSemverClause/toVulnerableVersions)
// had any direct unit test coverage before this file; this closes that gap.
// Run with:
//   node verdaccio-security-filter/test/smoke-version-matching.js

const assert = require('node:assert/strict');
const {
  versionSatisfies,
  MaliciousPackageStore,
  _resetSharedStoreForTests,
} = require('../malicious-packages.js');
const {
  normalizeRanges,
  rangeToSemverClause,
  toVulnerableVersions,
  parseLastKnownAffectedVersionRange,
} = require('../osv-client.js');

const NOOP_LOGGER = {warn() {}, error() {}, info() {}, fatal() {}};

function makeDisabledStore() {
  _resetSharedStoreForTests();
  return new MaliciousPackageStore(
    {enabled: false},
    {logger: NOOP_LOGGER, autoSchedule: false},
  );
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

  // --- versionSatisfies() --------------------------------------------------

  await check(
    'versionSatisfies: a version below an exclusive upper bound matches',
    () => {
      assert.equal(versionSatisfies('3.11.9', '<3.12.0'), true);
    },
  );

  await check(
    'versionSatisfies: the exact exclusive upper bound itself does not match',
    () => {
      assert.equal(versionSatisfies('3.12.0', '<3.12.0'), false);
    },
  );

  await check(
    'versionSatisfies: a version well above the range does not match -- the exact real-world reported bug',
    () => {
      assert.equal(versionSatisfies('6.7.4', '<3.12.0'), false);
    },
  );

  await check(
    'versionSatisfies: a lower-bound-inclusive, upper-bound-exclusive range',
    () => {
      assert.equal(versionSatisfies('1.0.0', '>=1.0.0 <2.0.0'), true);
      assert.equal(versionSatisfies('0.9.9', '>=1.0.0 <2.0.0'), false);
      assert.equal(versionSatisfies('2.0.0', '>=1.0.0 <2.0.0'), false);
    },
  );

  await check(
    'versionSatisfies: an OR-joined multi-clause range matches either clause',
    () => {
      const range = '>=1.0.0 <2.0.0 || >=3.0.0 <4.0.0';
      assert.equal(versionSatisfies('1.5.0', range), true);
      assert.equal(versionSatisfies('3.5.0', range), true);
      assert.equal(versionSatisfies('2.5.0', range), false);
    },
  );

  await check('versionSatisfies: "*" matches every version', () => {
    assert.equal(versionSatisfies('0.0.1', '*'), true);
    assert.equal(versionSatisfies('999.999.999', '*'), true);
  });

  await check(
    'versionSatisfies: includePrerelease means a prerelease still matches a plain range',
    () => {
      assert.equal(versionSatisfies('1.5.0-beta.1', '>=1.0.0 <2.0.0'), true);
    },
  );

  await check(
    'versionSatisfies: an unparseable, uncoercible version fails closed (matches anyway)',
    () => {
      assert.equal(versionSatisfies('not-a-version-at-all!!', '<3.12.0'), true);
    },
  );

  await check(
    'versionSatisfies: a coercible-but-not-strictly-valid version is still checked, not fail-opened',
    () => {
      assert.equal(versionSatisfies('v1.2.3', '<2.0.0'), true);
      assert.equal(versionSatisfies('v3.0.0', '<2.0.0'), false);
    },
  );

  // --- rangeToSemverClause() ------------------------------------------------

  await check(
    'rangeToSemverClause: introduced "0" + fixed -> exclusive upper bound only',
    () => {
      assert.equal(
        rangeToSemverClause({
          introduced: '0',
          fixed: '3.12.0',
          lastAffected: null,
        }),
        '<3.12.0',
      );
    },
  );

  await check(
    'rangeToSemverClause: a real (non-zero) introduced + fixed -> both bounds',
    () => {
      assert.equal(
        rangeToSemverClause({
          introduced: '1.0.0',
          fixed: '2.0.0',
          lastAffected: null,
        }),
        '>=1.0.0 <2.0.0',
      );
    },
  );

  await check(
    'rangeToSemverClause: no fixed, but a last_affected -> inclusive upper bound',
    () => {
      assert.equal(
        rangeToSemverClause({
          introduced: '0',
          fixed: null,
          lastAffected: '1.5.0',
        }),
        '<=1.5.0',
      );
    },
  );

  await check(
    'rangeToSemverClause: fixed wins over last_affected when both are present',
    () => {
      assert.equal(
        rangeToSemverClause({
          introduced: '0',
          fixed: '2.0.0',
          lastAffected: '1.5.0',
        }),
        '<2.0.0',
      );
    },
  );

  await check(
    'rangeToSemverClause: introduced with neither fixed nor last_affected -> open lower bound only',
    () => {
      assert.equal(
        rangeToSemverClause({
          introduced: '1.0.0',
          fixed: null,
          lastAffected: null,
        }),
        '>=1.0.0',
      );
    },
  );

  await check(
    'rangeToSemverClause: nothing at all (introduced "0", no fixed/last_affected) -> "*"',
    () => {
      assert.equal(
        rangeToSemverClause({introduced: '0', fixed: null, lastAffected: null}),
        '*',
      );
    },
  );

  await check(
    'rangeToSemverClause: an unparseable introduced is omitted, same as "0"',
    () => {
      assert.equal(
        rangeToSemverClause({
          introduced: 'not-a-version',
          fixed: '2.0.0',
          lastAffected: null,
        }),
        '<2.0.0',
      );
    },
  );

  await check(
    'rangeToSemverClause: an unparseable fixed leaves the range open above introduced (never falls through to last_affected)',
    () => {
      assert.equal(
        rangeToSemverClause({
          introduced: '1.0.0',
          fixed: 'garbage',
          lastAffected: '1.5.0',
        }),
        '>=1.0.0',
      );
    },
  );

  await check(
    'rangeToSemverClause: an unparseable last_affected with no fixed leaves the range fully open above introduced',
    () => {
      assert.equal(
        rangeToSemverClause({
          introduced: '1.0.0',
          fixed: null,
          lastAffected: 'garbage',
        }),
        '>=1.0.0',
      );
    },
  );

  // --- normalizeRanges() -----------------------------------------------------

  await check('normalizeRanges: a SEMVER range type is included', () => {
    const ranges = normalizeRanges({
      ranges: [
        {type: 'SEMVER', events: [{introduced: '0'}, {fixed: '3.12.0'}]},
      ],
    });
    assert.deepEqual(ranges, [
      {introduced: '0', fixed: '3.12.0', lastAffected: null},
    ]);
  });

  await check('normalizeRanges: an ECOSYSTEM range type is included', () => {
    const ranges = normalizeRanges({
      ranges: [
        {type: 'ECOSYSTEM', events: [{introduced: '0'}, {fixed: '1.0.0'}]},
      ],
    });
    assert.equal(ranges.length, 1);
  });

  await check(
    'normalizeRanges: a GIT (or any other) range type is skipped entirely',
    () => {
      const ranges = normalizeRanges({
        ranges: [{type: 'GIT', events: [{introduced: '0'}, {fixed: '1.0.0'}]}],
      });
      assert.deepEqual(ranges, []);
    },
  );

  await check(
    'normalizeRanges: multiple independent ranges on one affected[] entry are each kept',
    () => {
      const ranges = normalizeRanges({
        ranges: [
          {type: 'SEMVER', events: [{introduced: '0'}, {fixed: '1.0.0'}]},
          {type: 'SEMVER', events: [{introduced: '2.0.0'}, {fixed: '3.0.0'}]},
        ],
      });
      assert.equal(ranges.length, 2);
    },
  );

  await check(
    'normalizeRanges: last_known_affected_version_range fallback only applies when neither fixed nor last_affected came from events',
    () => {
      const withFallback = normalizeRanges({
        ranges: [{type: 'SEMVER', events: [{introduced: '0'}]}],
        database_specific: {last_known_affected_version_range: '<= 2.5.0'},
      });
      assert.deepEqual(withFallback, [
        {introduced: '0', fixed: null, lastAffected: '2.5.0'},
      ]);

      const withoutFallback = normalizeRanges({
        ranges: [
          {type: 'SEMVER', events: [{introduced: '0'}, {fixed: '1.0.0'}]},
        ],
        database_specific: {last_known_affected_version_range: '<= 2.5.0'},
      });
      assert.deepEqual(withoutFallback, [
        {introduced: '0', fixed: '1.0.0', lastAffected: null},
      ]);
    },
  );

  // --- parseLastKnownAffectedVersionRange() -----------------------------------

  await check(
    'parseLastKnownAffectedVersionRange: "< X" parses as fixed',
    () => {
      assert.deepEqual(parseLastKnownAffectedVersionRange('< 3.12.0'), {
        fixed: '3.12.0',
      });
    },
  );

  await check(
    'parseLastKnownAffectedVersionRange: "<= X" parses as lastAffected',
    () => {
      assert.deepEqual(parseLastKnownAffectedVersionRange('<= 3.12.0'), {
        lastAffected: '3.12.0',
      });
    },
  );

  await check(
    'parseLastKnownAffectedVersionRange: an unsupported operator/shape returns null',
    () => {
      assert.equal(parseLastKnownAffectedVersionRange('>= 1.0.0'), null);
      assert.equal(parseLastKnownAffectedVersionRange('1.0.0 - 2.0.0'), null);
    },
  );

  await check(
    'parseLastKnownAffectedVersionRange: a non-string input returns null',
    () => {
      assert.equal(parseLastKnownAffectedVersionRange(undefined), null);
      assert.equal(parseLastKnownAffectedVersionRange(null), null);
      assert.equal(parseLastKnownAffectedVersionRange(42), null);
    },
  );

  // --- toVulnerableVersions() ------------------------------------------------

  await check(
    'toVulnerableVersions: multiple ranges fold into one OR-joined clause',
    () => {
      const result = toVulnerableVersions([
        {introduced: '0', fixed: '1.0.0', lastAffected: null},
        {introduced: '2.0.0', fixed: '3.0.0', lastAffected: null},
      ]);
      assert.equal(result, '<1.0.0 || >=2.0.0 <3.0.0');
    },
  );

  await check(
    'toVulnerableVersions: explicit exact versions are folded in alongside ranges',
    () => {
      const result = toVulnerableVersions(
        [{introduced: '0', fixed: '1.0.0', lastAffected: null}],
        ['5.0.0', '5.0.1'],
      );
      assert.equal(result, '<1.0.0 || 5.0.0 || 5.0.1');
    },
  );

  await check(
    'toVulnerableVersions: exact versions alone with no ranges still works',
    () => {
      assert.equal(toVulnerableVersions([], ['5.0.0']), '5.0.0');
    },
  );

  await check('toVulnerableVersions: nothing at all returns null', () => {
    assert.equal(toVulnerableVersions([], []), null);
  });

  // --- getCveAdvisories(): the actual reported bug, end-to-end --------------

  await check(
    'getCveAdvisories: requires a non-empty versions array -- omitting it throws, never silently returns everything',
    () => {
      const store = makeDisabledStore();
      assert.throws(() => store.getCveAdvisories('verdaccio'));
      assert.throws(() => store.getCveAdvisories('verdaccio', []));
    },
  );

  await check(
    'getCveAdvisories: the exact real-world case -- verdaccio 6.7.4 is never reported against a "<3.12.0" advisory',
    () => {
      const store = makeDisabledStore();
      const cve = {
        id: 'GHSA-78j5-gcmf-vqc8',
        cveId: 'CVE-2019-14772',
        severity: 'moderate',
        cweIds: [],
        cvss3Score: null,
        cvss4Score: null,
        vulnerableVersions: '<3.12.0',
      };
      store._blocklist.set('verdaccio', {cves: [cve]});

      assert.deepEqual(
        store.getCveAdvisories('verdaccio', ['6.7.4']),
        [],
        'verdaccio 6.7.4 is nowhere near the vulnerable range and must not be reported',
      );
      assert.deepEqual(
        store.getCveAdvisories('verdaccio', ['3.11.0']),
        [cve],
        'a genuinely vulnerable version must still be reported',
      );
    },
  );

  await check(
    'getCveAdvisories: multiple requested versions -- reported if ANY of them is affected',
    () => {
      const store = makeDisabledStore();
      const cve = {
        id: 'GHSA-test-0001',
        cveId: 'CVE-2024-0001',
        severity: 'high',
        cweIds: [],
        cvss3Score: null,
        cvss4Score: null,
        vulnerableVersions: '<1.0.0',
      };
      store._blocklist.set('some-pkg', {cves: [cve]});

      assert.deepEqual(
        store.getCveAdvisories('some-pkg', ['2.0.0', '0.5.0']),
        [cve],
        'one affected version among several requested is enough to report the advisory',
      );
      assert.deepEqual(
        store.getCveAdvisories('some-pkg', ['2.0.0', '3.0.0']),
        [],
        'no requested version is affected -- nothing reported',
      );
    },
  );

  await check(
    'getCveAdvisories: a package with no blocklist entry at all returns empty, not a crash',
    () => {
      const store = makeDisabledStore();
      assert.deepEqual(
        store.getCveAdvisories('never-seen-package', ['1.0.0']),
        [],
      );
    },
  );

  console.log(`\n${passed} check(s) passed.`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
