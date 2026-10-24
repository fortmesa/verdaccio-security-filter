'use strict';

// Manual smoke test for the sensitivePaths check (see sensitive-paths.js and
// index.js's findSensitivePathTouch()) -- same real-HTTP-server harness as
// test/smoke.js, since the publish-time half of this check reads the raw
// request body (including the tarball attachment) itself. Run with:
//   node verdaccio-security-filter/test/smoke-sensitive-paths.js

const http = require('node:http');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const tar = require('tar');
const {SecurityFilter} = require('../index.js');

const NOOP_LOGGER = {warn() {}, error() {}, info() {}, fatal() {}};

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

function makeFakeStorage() {
  const existingByName = new Map();
  return {
    setExisting(name, versions, distTags = {}) {
      existingByName.set(name, {versions, 'dist-tags': distTags});
    },
    getPackage({name, callback}) {
      const existing = existingByName.get(name);
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

// Stands in for Verdaccio's Auth#allow_publish: every request here comes
// from a user allowed to publish (see test/smoke.js for the refusal paths).
const ALLOW_ALL_AUTH = {
  allow_publish(pkg, user, callback) {
    callback(null, true);
  },
};
const PUBLISHER = {name: 'tester', groups: ['$all', '$authenticated']};

// register_middlewares() registers several app.use() handlers; this
// dispatches through all of them in order, as Express would.
async function startServer(instance, storage) {
  const handlers = [];
  instance.register_middlewares(
    {use: fn => handlers.push(fn)},
    ALLOW_ALL_AUTH,
    storage,
  );

  const server = http.createServer((req, res) => {
    req.path = new URL(req.url, 'http://localhost').pathname;
    req.remote_user = PUBLISHER;
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
      const handler = handlers[index++];
      if (!handler) {
        res.status(201).json({ok: true});
        return;
      }
      handler(req, res, next);
    };
    next();
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return server;
}

function put(server, path_, body) {
  const {port} = server.address();
  return fetch(`http://127.0.0.1:${port}${path_}`, {
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

// Packs `files` (relativePath -> content) under a "package/" root, matching
// npm's own tarball convention, and returns a real gzip Buffer -- exercises
// sensitive-paths.js's extractTarballFiles() against actual tar bytes rather
// than a hand-faked Map.
// `links` (relativePath -> target) adds symbolic links; `dotPrefix` packs
// the root as "./package/..." instead of "package/...".
async function buildTarball(files, {links = {}, dotPrefix = false} = {}) {
  const tmpRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), 'sensitive-paths-test-'),
  );
  try {
    const pkgDir = path.join(tmpRoot, 'package');
    fs.mkdirSync(pkgDir, {recursive: true});
    for (const [relPath, content] of Object.entries(files)) {
      const filePath = path.join(pkgDir, relPath);
      fs.mkdirSync(path.dirname(filePath), {recursive: true});
      fs.writeFileSync(filePath, content);
    }
    for (const [relPath, target] of Object.entries(links)) {
      const linkPath = path.join(pkgDir, relPath);
      fs.mkdirSync(path.dirname(linkPath), {recursive: true});
      fs.symlinkSync(target, linkPath);
    }
    const chunks = [];
    await new Promise((resolve, reject) => {
      const stream = tar.create({cwd: tmpRoot, gzip: true}, [
        dotPrefix ? './package' : 'package',
      ]);
      stream.on('data', c => chunks.push(c));
      stream.on('end', resolve);
      stream.on('error', reject);
    });
    return Buffer.concat(chunks);
  } finally {
    fs.rmSync(tmpRoot, {recursive: true, force: true});
  }
}

function attachmentFor(packageName, version, tarballBuffer) {
  return {
    [`${packageName}-${version}.tgz`]: {
      content_type: 'application/octet-stream',
      data: tarballBuffer.toString('base64'),
      length: tarballBuffer.length,
    },
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

  function makeInstance(overrides = {}, optionsOverrides = {}) {
    return new SecurityFilter(
      {...overrides},
      {logger: NOOP_LOGGER, config: {}, ...optionsOverrides},
    );
  }

  // --- Read-time (filter_metadata) ---

  await check(
    'sensitivePaths (read-time): disabled by default -- a direct .ssh reference is left alone',
    async () => {
      const instance = makeInstance();
      const pkg = makePackageInfo('evil-pkg', {
        '1.0.0': {
          publishedAt: daysAgo(30),
          scripts: {postinstall: 'cat ~/.ssh/id_rsa > /tmp/out'},
        },
      });
      const result = await instance.filter_metadata(pkg);
      assert.ok('1.0.0' in result.versions);
    },
  );

  await check(
    'sensitivePaths (read-time): enabled with block -- a direct .ssh reference is removed',
    async () => {
      const instance = makeInstance({
        sensitivePaths: {enabled: true, block: true},
      });
      const pkg = makePackageInfo('evil-pkg', {
        '1.0.0': {
          publishedAt: daysAgo(30),
          scripts: {postinstall: 'cat ~/.ssh/id_rsa > /tmp/out'},
        },
      });
      const result = await instance.filter_metadata(pkg);
      assert.ok(!('1.0.0' in result.versions));
    },
  );

  await check(
    'sensitivePaths (read-time): enabled without block -- alerts (logs) but leaves the version installable',
    async () => {
      const logger = makeCapturingLogger();
      const instance = makeInstance(
        {sensitivePaths: {enabled: true}},
        {logger},
      );
      const pkg = makePackageInfo('evil-pkg', {
        '1.0.0': {
          publishedAt: daysAgo(30),
          scripts: {postinstall: 'cat ~/.ssh/id_rsa > /tmp/out'},
        },
      });
      const result = await instance.filter_metadata(pkg);
      assert.ok('1.0.0' in result.versions);
      assert.equal(logger.calls.warn.length, 1);
      const [fields] = logger.calls.warn[0];
      assert.equal(fields.matched, '.ssh');
    },
  );

  await check(
    'sensitivePaths (read-time): a benign install script is never flagged',
    async () => {
      const logger = makeCapturingLogger();
      const instance = makeInstance(
        {sensitivePaths: {enabled: true, block: true}},
        {logger},
      );
      const pkg = makePackageInfo('native-addon', {
        '1.0.0': {
          publishedAt: daysAgo(30),
          scripts: {install: 'node-gyp rebuild'},
        },
      });
      const result = await instance.filter_metadata(pkg);
      assert.ok('1.0.0' in result.versions);
      assert.equal(logger.calls.warn.length, 0);
      assert.equal(logger.calls.error.length, 0);
    },
  );

  await check(
    'sensitivePaths (read-time): allow-list bypasses even a blocked direct match',
    async () => {
      const instance = makeInstance({
        allow: ['evil-pkg'],
        sensitivePaths: {enabled: true, block: true},
      });
      const pkg = makePackageInfo('evil-pkg', {
        '1.0.0': {
          publishedAt: daysAgo(30),
          scripts: {postinstall: 'cat ~/.ssh/id_rsa > /tmp/out'},
        },
      });
      const result = await instance.filter_metadata(pkg);
      assert.ok('1.0.0' in result.versions);
    },
  );

  await check(
    'sensitivePaths: a custom paths list replaces the default entirely',
    async () => {
      const instance = makeInstance({
        sensitivePaths: {enabled: true, block: true, paths: ['.foo-secret']},
      });
      const sshPkg = makePackageInfo('evil-pkg-ssh', {
        '1.0.0': {
          publishedAt: daysAgo(30),
          scripts: {postinstall: 'cat ~/.ssh/id_rsa > /tmp/out'},
        },
      });
      const fooPkg = makePackageInfo('evil-pkg-foo', {
        '1.0.0': {
          publishedAt: daysAgo(30),
          scripts: {postinstall: 'cat ~/.foo-secret > /tmp/out'},
        },
      });
      const sshResult = await instance.filter_metadata(sshPkg);
      const fooResult = await instance.filter_metadata(fooPkg);
      assert.ok(
        '1.0.0' in sshResult.versions,
        '.ssh should no longer be flagged once paths: is overridden',
      );
      assert.ok(!('1.0.0' in fooResult.versions));
    },
  );

  // --- Publish-time (_checkPublish) ---

  await check(
    'sensitivePaths (publish): disabled by default -- a direct .npmrc reference publishes clean',
    async () => {
      const storage = makeFakeStorage();
      const server = await startServer(makeInstance(), storage);
      try {
        const {status} = await put(server, '/new-pkg', {
          versions: {
            '1.0.0': withScripts({postinstall: 'cp payload ~/.npmrc'}),
          },
        });
        assert.equal(status, 201);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'sensitivePaths (publish): enabled with block -- a direct .npmrc reference is rejected outright',
    async () => {
      const storage = makeFakeStorage();
      const logger = makeCapturingLogger();
      const server = await startServer(
        makeInstance({sensitivePaths: {enabled: true, block: true}}, {logger}),
        storage,
      );
      try {
        const {status, body} = await put(server, '/new-pkg', {
          versions: {
            '1.0.0': withScripts({postinstall: 'cp payload ~/.npmrc'}),
          },
        });
        assert.equal(status, 403);
        assert.match(body.reason, /SECURITY BLOCK/);
        assert.match(body.reason, /\.npmrc/);
        assert.equal(logger.calls.fatal.length, 1);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'sensitivePaths (publish): enabled without block -- alerts (logs) but the publish succeeds',
    async () => {
      const storage = makeFakeStorage();
      const logger = makeCapturingLogger();
      const server = await startServer(
        makeInstance({sensitivePaths: {enabled: true}}, {logger}),
        storage,
      );
      try {
        const {status} = await put(server, '/new-pkg', {
          versions: {
            '1.0.0': withScripts({postinstall: 'cp payload ~/.npmrc'}),
          },
        });
        assert.equal(status, 201);
        assert.equal(logger.calls.warn.length, 1);
        assert.equal(logger.calls.fatal.length, 0);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'sensitivePaths (publish): indirect -- a bundled script the install command invokes is resolved from the tarball and blocked',
    async () => {
      const storage = makeFakeStorage();
      const logger = makeCapturingLogger();
      const server = await startServer(
        makeInstance({sensitivePaths: {enabled: true, block: true}}, {logger}),
        storage,
      );
      try {
        const tarball = await buildTarball({
          'scripts/setup.js':
            "require('fs').readFileSync(require('os').homedir() + '/.aws/credentials')",
        });
        const {status, body} = await put(server, '/indirect-pkg', {
          versions: {
            '1.0.0': withScripts({postinstall: 'node scripts/setup.js'}),
          },
          _attachments: attachmentFor('indirect-pkg', '1.0.0', tarball),
        });
        assert.equal(status, 403);
        assert.match(body.reason, /SECURITY BLOCK/);
        assert.match(body.reason, /scripts\/setup\.js/);
        assert.match(body.reason, /\.aws/);
      } finally {
        server.close();
      }
    },
  );

  await check(
    "sensitivePaths (publish): with block, an invoked script the check can't read (no tarball attached) is rejected",
    async () => {
      const storage = makeFakeStorage();
      const server = await startServer(
        makeInstance({sensitivePaths: {enabled: true, block: true}}),
        storage,
      );
      try {
        // No _attachments at all: the install command only *invokes* a
        // local file, and with no tarball there's nothing to clear it with.
        const {status, body} = await put(server, '/indirect-pkg-2', {
          versions: {
            '1.0.0': withScripts({postinstall: 'node scripts/setup.js'}),
          },
        });
        assert.equal(status, 403);
        assert.match(body.reason, /could not be inspected/);
        assert.match(body.reason, /scripts\/setup\.js/);
      } finally {
        server.close();
      }
    },
  );

  await check(
    "sensitivePaths (publish): without block, an invoked script the check can't read alerts but the publish succeeds",
    async () => {
      const logger = makeCapturingLogger();
      const server = await startServer(
        makeInstance({sensitivePaths: {enabled: true}}, {logger}),
        makeFakeStorage(),
      );
      try {
        const {status} = await put(server, '/indirect-pkg-3', {
          versions: {
            '1.0.0': withScripts({postinstall: 'node scripts/setup.js'}),
          },
        });
        assert.equal(status, 201);
        assert.ok(
          logger.calls.warn.some(([fields]) =>
            /could not be inspected/.test(fields?.detail ?? ''),
          ),
        );
      } finally {
        server.close();
      }
    },
  );

  await check(
    'sensitivePaths (publish): a benign bundled script is not flagged',
    async () => {
      const storage = makeFakeStorage();
      const server = await startServer(
        makeInstance({sensitivePaths: {enabled: true, block: true}}),
        storage,
      );
      try {
        const tarball = await buildTarball({
          'scripts/setup.js': "console.log('building native addon')",
        });
        const {status} = await put(server, '/clean-pkg', {
          versions: {
            '1.0.0': withScripts({postinstall: 'node scripts/setup.js'}),
          },
          _attachments: attachmentFor('clean-pkg', '1.0.0', tarball),
        });
        assert.equal(status, 201);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'sensitivePaths (publish): the attachment is read whatever its key is named, as Verdaccio stores it',
    async () => {
      const server = await startServer(
        makeInstance({sensitivePaths: {enabled: true, block: true}}),
        makeFakeStorage(),
      );
      try {
        const tarball = await buildTarball({
          'scripts/setup.js':
            "require('fs').readFileSync(process.env.HOME + '/.npmrc')",
        });
        const {status, body} = await put(server, '/renamed-pkg', {
          versions: {
            '1.0.0': withScripts({postinstall: 'node scripts/setup.js'}),
          },
          _attachments: {
            'something-else.tgz': {data: tarball.toString('base64')},
          },
        });
        assert.equal(status, 403);
        // The tarball's own script was read: an unread one would block as
        // "could not be inspected" instead.
        assert.match(body.reason, /which itself references \.npmrc/);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'sensitivePaths (publish): however the command spells the path, the bundled file is found',
    async () => {
      const server = await startServer(
        makeInstance({sensitivePaths: {enabled: true, block: true}}),
        makeFakeStorage(),
      );
      try {
        const tarball = await buildTarball(
          {'scripts/setup.js': 'cat ~/.aws/credentials'},
          {dotPrefix: true},
        );
        for (const command of [
          'node ./scripts//setup.js',
          'node scripts/../scripts/setup.js',
          'sh ./scripts/./setup.js',
        ]) {
          const {status} = await put(server, '/spelled-pkg', {
            versions: {'1.0.0': withScripts({postinstall: command})},
            _attachments: attachmentFor('spelled-pkg', '1.0.0', tarball),
          });
          assert.equal(status, 403, command);
        }
      } finally {
        server.close();
      }
    },
  );

  await check(
    'sensitivePaths (publish): an invoked script the tarball holds as a link is rejected under block',
    async () => {
      const server = await startServer(
        makeInstance({sensitivePaths: {enabled: true, block: true}}),
        makeFakeStorage(),
      );
      try {
        const tarball = await buildTarball(
          {'real.js': 'harmless'},
          {links: {'scripts/setup.js': '/home/user/.ssh/id_rsa'}},
        );
        const {status, body} = await put(server, '/linked-pkg', {
          versions: {
            '1.0.0': withScripts({postinstall: 'node scripts/setup.js'}),
          },
          _attachments: attachmentFor('linked-pkg', '1.0.0', tarball),
        });
        assert.equal(status, 403);
        assert.match(body.reason, /it is a link/);
      } finally {
        server.close();
      }
    },
  );

  await check(
    'extractTarballFiles: refuses past its inflated-size, entry-count and per-file limits, and nested compression',
    async () => {
      const {extractTarballFiles} = require('../sensitive-paths.js');
      const zlib = require('node:zlib');
      const wanted = new Set(['scripts/setup.js']);
      const big = await buildTarball({
        'scripts/setup.js': 'a'.repeat(200000),
        'filler.txt': 'b'.repeat(400000),
      });
      await assert.rejects(
        extractTarballFiles(big, wanted, {
          inflatedBytes: 100000,
          entries: 1000,
          fileBytes: 1e9,
        }),
        err =>
          err.code === 'TARBALL_LIMIT' && /inflates past/.test(err.message),
      );
      await assert.rejects(
        extractTarballFiles(big, wanted, {
          inflatedBytes: 1e9,
          entries: 1000,
          fileBytes: 1000,
        }),
        err => err.code === 'TARBALL_LIMIT' && /larger than/.test(err.message),
      );
      const many = await buildTarball(
        Object.fromEntries(
          Array.from({length: 30}, (_, i) => [`f${i}.txt`, 'x']),
        ),
      );
      await assert.rejects(
        extractTarballFiles(many, wanted, {
          inflatedBytes: 1e9,
          entries: 10,
          fileBytes: 1e9,
        }),
        err =>
          err.code === 'TARBALL_LIMIT' &&
          /more than 10 entries/.test(err.message),
      );
      await assert.rejects(
        extractTarballFiles(zlib.gzipSync(big), wanted),
        /compressed more than once/,
      );
      await assert.rejects(
        extractTarballFiles(Buffer.from('not an archive at all'), wanted),
        /neither a gzip nor a tar/,
      );
      const ok = await extractTarballFiles(big, wanted);
      assert.equal(ok.files.get('scripts/setup.js').length, 200000);
    },
  );

  await check(
    'sensitivePaths (publish): a tarball past the inspection limits leaves the invoked script unreadable, so block rejects it',
    async () => {
      const zlib = require('node:zlib');
      const server = await startServer(
        makeInstance({sensitivePaths: {enabled: true, block: true}}),
        makeFakeStorage(),
      );
      try {
        // A gzip of a gzip: refused before anything is inflated past the
        // outer layer.
        const tarball = zlib.gzipSync(
          await buildTarball({'scripts/setup.js': 'echo hi'}),
        );
        const {status, body} = await put(server, '/bomb-pkg', {
          versions: {
            '1.0.0': withScripts({postinstall: 'node scripts/setup.js'}),
          },
          _attachments: attachmentFor('bomb-pkg', '1.0.0', tarball),
        });
        assert.equal(status, 403);
        assert.match(body.reason, /could not be inspected/);
      } finally {
        server.close();
      }
    },
  );

  console.log(`\n${passed} check(s) passed.`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
