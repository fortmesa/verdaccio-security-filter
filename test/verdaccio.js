'use strict';

// The plugin inside a real Verdaccio, as both its filter and its middleware,
// in front of a fake uplink, with a webhook receiver that counts every
// alert. Proves the publish gate sees every route Verdaccio publishes
// through, answers only callers Verdaccio would let publish, bounds and
// parses the body the way Verdaccio does, and inspects the tarball
// Verdaccio actually stores. Run with:
//   node test/verdaccio.js
// VERDACCIO_BIN points it at another Verdaccio build, e.g. the one
// fm-npmjs deploys:
//   VERDACCIO_BIN=../fm-npmjs/node_modules/verdaccio/bin/verdaccio node test/verdaccio.js

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const {spawn} = require('node:child_process');
const tar = require('tar');

const PLUGIN_ROOT = path.join(__dirname, '..');
// verdaccio's package exports don't include its bin, so it's found by path.
const VERDACCIO_BIN =
  process.env.VERDACCIO_BIN ??
  path.join(PLUGIN_ROOT, 'node_modules', 'verdaccio', 'bin', 'verdaccio');

// A registry with one package, remote-pkg, published long ago.
function startFakeUplink() {
  const requests = [];
  const server = http.createServer((req, res) => {
    requests.push(`${req.method} ${req.url.split('?')[0]}`);
    res.setHeader('content-type', 'application/json');
    if (req.url === '/remote-pkg') {
      const base = `http://127.0.0.1:${server.address().port}`;
      return res.end(
        JSON.stringify({
          name: 'remote-pkg',
          'dist-tags': {latest: '1.0.0'},
          versions: {
            '1.0.0': {
              name: 'remote-pkg',
              version: '1.0.0',
              dist: {tarball: `${base}/remote-pkg/-/remote-pkg-1.0.0.tgz`},
            },
          },
          time: {'1.0.0': '2020-01-01T00:00:00.000Z'},
        }),
      );
    }
    res.statusCode = 404;
    res.end('{"error":"not found"}');
  });
  return new Promise(resolve =>
    server.listen(0, '127.0.0.1', () => resolve({server, requests})),
  );
}

function startWebhookReceiver() {
  const alerts = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => (body += chunk));
    req.on('end', () => {
      alerts.push(JSON.parse(body));
      res.end('ok');
    });
  });
  return new Promise(resolve =>
    server.listen(0, '127.0.0.1', () => resolve({server, alerts})),
  );
}

function freePort() {
  return new Promise(resolve => {
    const s = http.createServer().listen(0, '127.0.0.1', () => {
      const {port} = s.address();
      s.close(() => resolve(port));
    });
  });
}

async function waitForUp(url, proc) {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    if (proc.exitCode != null) break;
    try {
      if ((await fetch(url)).ok) return;
    } catch {
      // not up yet
    }
    await new Promise(r => setTimeout(r, 200));
  }
  throw new Error(`verdaccio never came up:\n${proc.getOutput()}`);
}

// A real .tgz holding `files` under package/, as npm packs it.
async function packTarball(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-pack-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const file = path.join(root, 'package', rel);
      fs.mkdirSync(path.dirname(file), {recursive: true});
      fs.writeFileSync(file, content);
    }
    const chunks = [];
    await new Promise((resolve, reject) => {
      const stream = tar.create({cwd: root, gzip: true}, ['package']);
      stream.on('data', c => chunks.push(c));
      stream.on('end', resolve);
      stream.on('error', reject);
    });
    return Buffer.concat(chunks);
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
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

  const {server: uplink} = await startFakeUplink();
  const receiver = await startWebhookReceiver();
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'security-filter-'));
  const plugins = path.join(work, 'plugins');
  fs.mkdirSync(path.join(plugins, '@fortmesa'), {recursive: true});
  fs.symlinkSync(
    PLUGIN_ROOT,
    path.join(plugins, '@fortmesa', 'verdaccio-security-filter'),
    'dir',
  );
  fs.writeFileSync(path.join(work, 'htpasswd'), '');
  fs.writeFileSync(
    path.join(work, 'config.yaml'),
    `
storage: ${path.join(work, 'storage')}
plugins: ${plugins}
max_body_size: 1mb
auth:
  htpasswd:
    file: ${path.join(work, 'htpasswd')}
    max_users: 1000
security:
  api:
    legacy: false
    jwt:
      sign:
        expiresIn: 7d
uplinks:
  fake:
    url: http://127.0.0.1:${uplink.address().port}/
packages:
  '**':
    access: $authenticated
    publish: alice
    proxy: fake
filters:
  '@fortmesa/verdaccio-security-filter':
    packageAge:
      minDays: 0
    block:
      - 'evil-*'
      - '@evil/*'
    scriptHeuristics:
      enabled: true
      blockShellPipe: true
    sensitivePaths:
      enabled: true
      block: true
    webhook:
      url: http://127.0.0.1:${receiver.server.address().port}/hook
      body: '{"event":"{{event}}","pkg":"{{pkg}}","ver":"{{ver}}"}'
      content-type: application/json
middlewares:
  '@fortmesa/verdaccio-security-filter':
    blockPublishWithNewScripts: true
    blockPublishMatches: true
log: {type: stdout, format: pretty, level: warn}
`,
  );

  const port = await freePort();
  const registry = `http://127.0.0.1:${port}`;
  const proc = spawn(
    process.execPath,
    [
      VERDACCIO_BIN,
      '--config',
      path.join(work, 'config.yaml'),
      '--listen',
      `127.0.0.1:${port}`,
    ],
    {stdio: ['ignore', 'pipe', 'pipe']},
  );
  let output = '';
  proc.stdout.on('data', d => (output += d));
  proc.stderr.on('data', d => (output += d));
  proc.getOutput = () => output;

  // Every request gets 10s, so a gate that never answers fails the check
  // instead of hanging the run.
  const request = (
    method,
    url,
    {token, body, type = 'application/json'} = {},
  ) =>
    fetch(`${registry}${url}`, {
      method,
      headers: {
        ...(token ? {authorization: `Bearer ${token}`} : {}),
        ...(body !== undefined ? {'content-type': type} : {}),
      },
      body,
      signal: AbortSignal.timeout(10000),
    });

  // A publish document for one version of `name`. `scripts` goes into the
  // version, `files` into its tarball, and `attachmentName` overrides the
  // name npm would give the attachment.
  async function publishDoc(
    name,
    version,
    {scripts, files = {'index.js': ''}, attachmentName, versions = {}} = {},
  ) {
    const tgz = await packTarball({
      'package.json': JSON.stringify({name, version}),
      ...files,
    });
    const file = attachmentName ?? `${name.split('/').pop()}-${version}.tgz`;
    return JSON.stringify({
      _id: name,
      name,
      'dist-tags': {latest: version},
      versions: {
        ...versions,
        [version]: {
          name,
          version,
          ...(scripts ? {scripts} : {}),
          dist: {
            tarball: `${registry}/${name}/-/${file}`,
            shasum: crypto.createHash('sha1').update(tgz).digest('hex'),
          },
        },
      },
      _attachments: {
        [file]: {
          content_type: 'application/octet-stream',
          data: tgz.toString('base64'),
          length: tgz.length,
        },
      },
    });
  }

  try {
    await waitForUp(`${registry}/-/ping`, proc);
    const verdaccioVersion = JSON.parse(
      fs.readFileSync(
        path.join(path.dirname(VERDACCIO_BIN), '..', 'package.json'),
      ),
    ).version;
    console.log(`verdaccio ${verdaccioVersion}, node ${process.version}`);

    async function addUser(name) {
      const res = await request('PUT', `/-/user/org.couchdb.user:${name}`, {
        body: JSON.stringify({
          name,
          password: crypto.randomBytes(12).toString('hex'),
        }),
      });
      const body = await res.json();
      assert.ok(body.token, `registering ${name}: ${JSON.stringify(body)}`);
      return body.token;
    }
    const alice = await addUser('alice'); // may publish
    const bob = await addUser('bob'); // authenticated, may not publish

    const settle = () => new Promise(r => setTimeout(r, 300));
    // Alerts are fire-and-forget, so an earlier check's may still be on
    // its way: let them land before counting.
    const alertCount = () => receiver.alerts.length;
    const countAlerts = async () => {
      await settle();
      return alertCount();
    };

    await check('a clean publish goes through and reads back', async () => {
      const res = await request('PUT', '/good-pkg', {
        token: alice,
        body: await publishDoc('good-pkg', '1.0.0'),
      });
      assert.equal(res.status, 201, await res.text());
      const read = await request('GET', '/good-pkg', {token: alice});
      assert.equal(read.status, 200);
      assert.ok((await read.json()).versions['1.0.0']);
    });

    await check(
      'a version that newly introduces an install script is refused, with one alert',
      async () => {
        const before = await countAlerts();
        const res = await request('PUT', '/good-pkg', {
          token: alice,
          body: await publishDoc('good-pkg', '1.1.0', {
            scripts: {postinstall: 'node setup.js'},
          }),
        });
        assert.equal(res.status, 403);
        assert.match((await res.json()).reason, /SECURITY BLOCK/);
        await settle();
        assert.equal(alertCount(), before + 1);
        assert.equal(receiver.alerts.at(-1).event, 'publish_blocked_script');
      },
    );

    await check(
      'the same version sent through /:package/-rev/:revision is refused too, and not stored',
      async () => {
        const current = await (
          await request('GET', '/good-pkg', {token: alice})
        ).json();
        const res = await request(
          'PUT',
          `/good-pkg/-rev/${current._rev ?? '1-x'}`,
          {
            token: alice,
            body: await publishDoc('good-pkg', '1.2.0', {
              scripts: {postinstall: 'node setup.js'},
              versions: current.versions,
            }),
          },
        );
        assert.equal(res.status, 403, await res.text());
        const after = await (
          await request('GET', '/good-pkg', {token: alice})
        ).json();
        assert.equal(after.versions['1.2.0'], undefined);
      },
    );

    await check(
      'a scoped name with a literal slash is matched by its block rule',
      async () => {
        const res = await request('PUT', '/@evil/pkg', {
          token: alice,
          body: await publishDoc('@evil/pkg', '1.0.0'),
        });
        const text = await res.text();
        assert.equal(res.status, 403, text);
        assert.match(JSON.parse(text).reason, /@evil\/pkg@1\.0\.0/);
      },
    );

    await check(
      "an anonymous publish gets Verdaccio's own 401, and fires no alert",
      async () => {
        const before = await countAlerts();
        const res = await request('PUT', '/evil-pkg', {
          body: await publishDoc('evil-pkg', '1.0.0'),
        });
        assert.equal(res.status, 401);
        assert.doesNotMatch(await res.text(), /SECURITY BLOCK/);
        await settle();
        assert.equal(alertCount(), before);
      },
    );

    await check(
      "a user who may not publish gets Verdaccio's own 403, and fires no alert",
      async () => {
        const before = await countAlerts();
        const res = await request('PUT', '/evil-pkg', {
          token: bob,
          body: await publishDoc('evil-pkg', '1.0.0'),
        });
        assert.equal(res.status, 403);
        assert.doesNotMatch(await res.text(), /SECURITY BLOCK/);
        await settle();
        assert.equal(alertCount(), before);
      },
    );

    await check(
      'a body over max_body_size gets 413 and a malformed one 400',
      async () => {
        const big = await request('PUT', '/big-pkg', {
          token: alice,
          body: JSON.stringify({
            versions: {},
            filler: 'x'.repeat(1.5 * 1024 * 1024),
          }),
        });
        assert.equal(big.status, 413);
        const bad = await request('PUT', '/bad-pkg', {
          token: alice,
          body: '{"versions": {',
        });
        assert.equal(bad.status, 400);
      },
    );

    await check(
      'a version entry that is not an object gets 400, and Verdaccio keeps serving',
      async () => {
        const res = await request('PUT', '/null-pkg', {
          token: alice,
          body: JSON.stringify({name: 'null-pkg', versions: {'1.0.0': null}}),
        });
        assert.equal(res.status, 400);
        assert.equal((await request('GET', '/-/ping')).status, 200);
      },
    );

    await check(
      'the stored tarball is inspected whatever its attachment is named',
      async () => {
        const res = await request('PUT', '/sneaky-pkg', {
          token: alice,
          body: await publishDoc('sneaky-pkg', '1.0.0', {
            scripts: {postinstall: 'node scripts/setup.js'},
            files: {
              'scripts/setup.js':
                "require('fs').readFileSync(require('os').homedir() + '/.npmrc')",
            },
            attachmentName: 'renamed.tgz',
          }),
        });
        const text = await res.text();
        assert.equal(res.status, 403, text);
        assert.match(JSON.parse(text).reason, /\.npmrc/);
      },
    );

    await check(
      "a first local publish of a name the uplink already has is checked against the uplink's history",
      async () => {
        // Verdaccio itself accepts this publish (it stores 2.0.0 next to
        // the uplink's 1.0.0); the clean 1.0.0 upstream is the baseline the
        // new postinstall breaks.
        const res = await request('PUT', '/remote-pkg', {
          token: alice,
          body: await publishDoc('remote-pkg', '2.0.0', {
            scripts: {postinstall: 'node setup.js'},
          }),
        });
        assert.equal(res.status, 403, await res.text());
        const read = await (
          await request('GET', '/remote-pkg', {token: alice})
        ).json();
        assert.equal(read.versions?.['2.0.0'], undefined);
        assert.ok(
          read.versions?.['1.0.0'],
          'the upstream version is still served',
        );
      },
    );
  } finally {
    proc.kill();
    uplink.close();
    receiver.server.close();
    if (process.exitCode) {
      console.error('\n--- verdaccio output ---\n' + proc.getOutput());
    }
    fs.rmSync(work, {recursive: true, force: true});
  }

  console.log(`\n${passed} check(s) passed.`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
