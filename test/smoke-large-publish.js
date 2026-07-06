'use strict';

// Manual smoke test -- no framework, matching test/smoke.js's house style
// (see that file's own comment for why this spins up a real local HTTP
// server rather than a hand-faked req/res: the publish gate reads the
// request body itself via body-parser, ahead of Verdaccio's own parser, so
// it needs a genuine request stream to mean anything).
//
// Regression coverage for a real production failure: publishing
// @fortmesa/verdaccio-generic-oidc (a ~54KB, multi-file TypeScript build)
// through this gate intermittently/consistently failed with body-parser's
// "request size did not match content length" -- smaller packages
// (verdaccio-oidc-auth, verdaccio-offline-enforcer, verdaccio-attestations)
// published cleanly, verdaccio-security-filter itself failed once then
// succeeded on retry, verdaccio-generic-oidc failed 3/3 times. Removing
// blockPublishWithNewScripts/blockPublishMatches (which is what puts
// _checkPublish's own body-parser read ahead of Verdaccio's own) made it
// publish successfully, isolating the race to this plugin's own read
// rather than anything upstream (ALB/ingress). This test pads a publish
// body well past that real failure's size to check whether the race is
// reproducible over a plain loopback connection (no proxy/ALB involved) --
// if this test passes reliably, either the race isn't present in the
// current code, or it needs something about the real network path
// (chunked delivery, proxy buffering) that loopback doesn't recreate;
// if it fails, the race is confirmed local to this plugin's own
// _parseJsonBody call, independent of any external infra.
//
// Run with:
//   node verdaccio-security-filter/test/smoke-large-publish.js

const http = require('node:http');
const assert = require('node:assert/strict');
const {SecurityFilter} = require('../index.js');

const NOOP_LOGGER = {warn() {}, error() {}, info() {}, fatal() {}};

// Same minimal Storage#getPackage stand-in as test/smoke.js -- a brand-new
// package (no existing versions) is enough to reach _checkPublish's actual
// body-parsing work without needing to exercise its match/block logic.
function makeFakeStorage() {
  return {
    getPackage({callback}) {
      callback({status: 404}, null);
    },
  };
}

// Same harness as test/smoke.js's startServer(): registers against a real
// http server so body-parser reads a genuine request stream, and shims just
// the Express-specific bits (req.path, res.status/json) the plugin relies
// on. Duplicated rather than imported -- this repo's smoke tests are each
// self-contained (see test/smoke-legacy-audit.js, test/smoke-malicious-
// packages.js), not sharing a test-utils module.
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
    headers: {'content-type': 'application/json'},
    body: JSON.stringify(body),
  }).then(async res => ({
    status: res.status,
    body: await res.json().catch(() => null),
  }));
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

  // Real k8s configmap has both flags true (see fm-npmjs's
  // k8s/02-configmap.yaml) -- either alone is enough to route the request
  // through this plugin's own _parseJsonBody, but matching both keeps this
  // test faithful to the actual deployed condition that failed.
  for (const sizeBytes of [100_000, 500_000, 2_000_000]) {
    await check(
      `a ${sizeBytes}-byte publish body is read in full by the publish gate, no content-length mismatch`,
      async () => {
        const instance = new SecurityFilter(
          {blockPublishWithNewScripts: true, blockPublishMatches: true},
          {logger: NOOP_LOGGER},
        );
        const server = await startServer(instance, makeFakeStorage());
        try {
          const versionMeta = {
            version: '1.0.0',
            dist: {tarball: 'https://example/big-pkg/-/big-pkg-1.0.0.tgz'},
            // Stands in for a real publish's base64-encoded tarball
            // attachment -- what actually made @fortmesa/verdaccio-generic-
            // oidc's real request body ~54KB. This gate only ever reads
            // req.body.versions, so a filler string here exercises the same
            // body-parser code path as a real attachment would.
            _filler: 'x'.repeat(sizeBytes),
          };
          const {status, body} = await put(server, '/big-pkg', {
            versions: {'1.0.0': versionMeta},
          });
          assert.equal(
            status,
            201,
            `expected the publish gate to pass the large body through, got ${status}: ${JSON.stringify(body)}`,
          );
        } finally {
          server.close();
        }
      },
    );
  }

  console.log(`\n${passed} check(s) passed.`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
