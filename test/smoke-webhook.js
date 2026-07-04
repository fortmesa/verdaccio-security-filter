'use strict';

// Manual smoke test for the webhook feature -- no framework, matching this
// repo's house style (see test/smoke.js). Run with:
//   node verdaccio-security-filter/test/smoke-webhook.js
// Spins up a real local HTTP server as the webhook receiver, exactly like
// test/smoke-malicious-packages.js does for the fake OSV feed.

const http = require('node:http');
const assert = require('node:assert/strict');
const {SecurityFilter} = require('../index.js');

const NOOP_LOGGER = {warn() {}, error() {}, info() {}, fatal() {}};

function makeCapturingLogger() {
  const calls = {warn: [], error: []};
  return {
    warn: (...args) => calls.warn.push(args),
    error: (...args) => calls.error.push(args),
    info() {},
    calls,
  };
}

// Records every request it receives (method, path, headers, body) so a test
// can assert on exactly what the plugin sent, not just that "something" hit
// the receiver.
async function startWebhookReceiver() {
  const requests = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => (body += chunk));
    req.on('end', () => {
      requests.push({
        method: req.method,
        path: req.url,
        headers: req.headers,
        body,
      });
      res.statusCode = 200;
      res.end('ok');
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const {port} = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    close: () => new Promise(resolve => server.close(resolve)),
  };
}

// Same minimal Storage#getPackage stand-in as test/smoke.js.
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

async function waitFor(predicate, {timeoutMs = 2000, intervalMs = 10} = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
  throw new Error('waitFor: condition never became true');
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

  await check(
    'a configured webhook fires as a POST with substituted body/url/headers on a publish rejection',
    async () => {
      const receiver = await startWebhookReceiver();
      try {
        const storage = makeFakeStorage();
        const instance = new SecurityFilter(
          {blockPublishMatches: true},
          {
            logger: NOOP_LOGGER,
            config: {
              filters: {
                '@fortmesa/verdaccio-security-filter': {
                  block: ['bad-pkg'],
                  webhook: {
                    url: `${receiver.url}/hook/{{pkg}}`,
                    body: '{"pkg":"{{pkg}}","ver":"{{ver}}","reason":"{{reason}}"}',
                    'x-event': '{{event}}',
                    'content-type': 'application/json',
                  },
                },
              },
            },
          },
        );
        const server = await startServer(instance, storage);
        try {
          const {status} = await put(server, '/bad-pkg', {
            versions: {'1.0.0': withScripts({})},
          });
          assert.equal(status, 403);
          await waitFor(() => receiver.requests.length > 0);
          const [req] = receiver.requests;
          assert.equal(req.method, 'POST');
          assert.equal(req.path, '/hook/bad-pkg');
          assert.equal(req.headers['x-event'], 'publish_blocked_rule');
          assert.equal(req.headers['content-type'], 'application/json');
          const payload = JSON.parse(req.body);
          assert.equal(payload.pkg, 'bad-pkg');
          assert.equal(payload.ver, '1.0.0');
          assert.match(payload.reason, /SECURITY BLOCK/);
        } finally {
          server.close();
        }
      } finally {
        await receiver.close();
      }
    },
  );

  await check('a webhook with no configured body fires as a GET', async () => {
    const receiver = await startWebhookReceiver();
    try {
      const storage = makeFakeStorage();
      const instance = new SecurityFilter(
        {blockPublishMatches: true},
        {
          logger: NOOP_LOGGER,
          config: {
            filters: {
              '@fortmesa/verdaccio-security-filter': {
                block: ['bad-pkg'],
                webhook: {url: `${receiver.url}/ping`},
              },
            },
          },
        },
      );
      const server = await startServer(instance, storage);
      try {
        await put(server, '/bad-pkg', {versions: {'1.0.0': withScripts({})}});
        await waitFor(() => receiver.requests.length > 0);
        const [req] = receiver.requests;
        assert.equal(req.method, 'GET');
        assert.equal(req.body, '');
      } finally {
        server.close();
      }
    } finally {
      await receiver.close();
    }
  });

  await check(
    'constructor throws loud when webhook is configured with no url',
    () => {
      assert.throws(
        () =>
          new SecurityFilter(
            {},
            {
              logger: NOOP_LOGGER,
              config: {
                filters: {
                  '@fortmesa/verdaccio-security-filter': {
                    webhook: {body: 'no url here'},
                  },
                },
              },
            },
          ),
        /webhook is configured but has no url/,
      );
    },
  );

  await check(
    'the middlewares: instance resolves allow/webhook from the canonical filters: section, not its own (smaller) config',
    async () => {
      const receiver = await startWebhookReceiver();
      try {
        // This instance's OWN config block (what a real middlewares: section
        // for this plugin actually looks like) has neither `allow` nor
        // `webhook` -- both must come from options.config.filters
        // ['@fortmesa/verdaccio-security-filter'], exactly like a real
        // Verdaccio deployment's filters: + middlewares: split. Regression
        // test for the bare-'security-filter'-key bug this now fixes.
        const storage = makeFakeStorage();
        const fakeStore = makeFakeBlocklist(name =>
          ['evil-pkg', 'other-evil-pkg'].includes(name)
            ? {type: 'mal', malIds: ['MAL-1']}
            : null,
        );
        const instance = new SecurityFilter(
          {blockPublishMatches: true},
          {
            logger: NOOP_LOGGER,
            maliciousPackageStore: fakeStore,
            config: {
              filters: {
                '@fortmesa/verdaccio-security-filter': {
                  allow: ['evil-pkg'],
                  webhook: {url: `${receiver.url}/ping`},
                },
              },
            },
          },
        );
        const server = await startServer(instance, storage);
        try {
          const {status} = await put(server, '/evil-pkg', {
            versions: {'1.0.0': withScripts({})},
          });
          // allow: ['evil-pkg'] from the shared filters: section must
          // exempt this publish, even though blockPublishMatches is set on
          // this (middlewares:-shaped) instance directly.
          assert.equal(
            status,
            201,
            'allow-list from the canonical filters: section should have exempted this publish',
          );
        } finally {
          server.close();
        }

        // Separately, force an actual block (different package, not
        // allow-listed) and confirm the webhook from that SAME canonical
        // section still fires from this middlewares:-shaped instance.
        const server2 = await startServer(instance, storage);
        try {
          await put(server2, '/other-evil-pkg', {
            versions: {'1.0.0': withScripts({})},
          });
        } finally {
          server2.close();
        }
        await waitFor(() => receiver.requests.length > 0);
      } finally {
        await receiver.close();
      }
    },
  );

  console.log(`\n${passed} check(s) passed.`);
}

main();
