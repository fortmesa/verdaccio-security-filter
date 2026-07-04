'use strict';

// Manual smoke test for the OSV sync subsystem (osv-client.js +
// malicious-packages.js) -- no framework, matching test/smoke.js's house
// style. Run with:
//   node verdaccio-security-filter/test/smoke-malicious-packages.js
// Spins up a real local HTTP server standing in for OSV's endpoints
// (all.zip / modified_id.csv / <ID>.json, with real ETag/304 handling), and
// a hand-rolled fake DynamoDB client -- this repo has no precedent for
// spinning up a real/emulated AWS service in tests (see makeFakeStorage()
// in test/smoke.js for the same "fake exactly the interface under test
// uses" approach applied to Verdaccio's own Storage).

const http = require('node:http');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const yazl = require('yazl');
const {
  ScanCommand,
  GetCommand,
  PutCommand,
  DeleteCommand,
  BatchWriteCommand,
} = require('@aws-sdk/lib-dynamodb');
const {
  MaliciousPackageStore,
  _resetSharedStoreForTests,
} = require('../malicious-packages.js');
const {createDynamoDbStore} = require('../dynamodb-store.js');

const NOOP_LOGGER = {warn() {}, error() {}, info() {}};

function makeCapturingLogger() {
  const calls = {warn: [], error: []};
  return {
    warn: (...args) => calls.warn.push(args),
    error: (...args) => calls.error.push(args),
    info() {},
    calls,
  };
}

// Minimal Storage#getPackage stand-in -- same shape test/smoke.js and
// test/smoke-webhook.js use, just under the name this file's own tests
// reach for.
function makeFakeRegistryStorage() {
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

// Same webhook-receiver stand-in as test/smoke-webhook.js.
async function startWebhookReceiver() {
  const requests = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => (body += chunk));
    req.on('end', () => {
      requests.push({method: req.method, path: req.url, body});
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

async function waitFor(predicate, {timeoutMs = 2000, intervalMs = 10} = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
  throw new Error('waitFor: condition never became true');
}

// `origins` mimics database_specific['malicious-packages-origins'] --
// defaults to a single origin (the most common real-world case: 155,429 of
// 215,113 live npm MAL records have exactly one) so existing tests that
// don't care about origin-count/source filtering still get blocked under
// the default osv.malware.minOrigin: 1 without having to think about it.
function makeOsvRecord({
  id,
  modified,
  packageName,
  introduced = '0',
  fixed = null,
  withdrawn = false,
  origins = [{source: 'ghsa-malware'}],
}) {
  const events = [{introduced}];
  if (fixed) events.push({fixed});
  return {
    schema_version: '1.7.3',
    id,
    published: modified,
    modified,
    ...(withdrawn ? {withdrawn: modified} : {}),
    summary: `Malicious code in ${packageName} (npm)`,
    affected: [
      {
        package: {
          name: packageName,
          ecosystem: 'npm',
          purl: `pkg:npm/${packageName}`,
        },
        ranges: [{type: 'SEMVER', events}],
      },
    ],
    database_specific: {
      'malicious-packages-origins': origins,
    },
  };
}

// A real CVE-backed GHSA record fixture -- severity/cwe_ids/aliases live
// under database_specific/aliases, same shape as the real OSV feed
// (verified against live GHSA-2234-fmw7-43wr earlier this session).
function makeGhsaRecord({
  id,
  modified,
  packageName,
  introduced = '0',
  fixed = null,
  withdrawn = false,
  severity = 'HIGH',
  cweIds = ['CWE-79'],
  cveId,
}) {
  const events = [{introduced}];
  if (fixed) events.push({fixed});
  return {
    schema_version: '1.7.3',
    id,
    published: modified,
    modified,
    ...(withdrawn ? {withdrawn: modified} : {}),
    ...(cveId ? {aliases: [cveId]} : {}),
    summary: `Vulnerability in ${packageName} (npm)`,
    affected: [
      {
        package: {
          name: packageName,
          ecosystem: 'npm',
          purl: `pkg:npm/${packageName}`,
        },
        ranges: [{type: 'SEMVER', events}],
      },
    ],
    database_specific: {severity, cwe_ids: cweIds},
  };
}

function buildZip(records) {
  return new Promise((resolve, reject) => {
    const zipfile = new yazl.ZipFile();
    for (const record of records) {
      zipfile.addBuffer(
        Buffer.from(JSON.stringify(record)),
        `npm/${record.id}.json`,
      );
    }
    const chunks = [];
    zipfile.outputStream.on('data', c => chunks.push(c));
    zipfile.outputStream.on('end', () => resolve(Buffer.concat(chunks)));
    zipfile.outputStream.on('error', reject);
    zipfile.end();
  });
}

// A real local HTTP server standing in for OSV's endpoints, with
// controllable fixture content and real conditional-GET (ETag) handling so
// tests can assert on both the 200 and 304 branches concretely.
async function startMockOsvServer() {
  let zipBuffer = Buffer.alloc(0);
  let csvRows = []; // [{modified, id}], newest-first, matching the real feed's order
  let csvEtag = 'etag-v1';
  const recordsById = new Map();
  let requestCount = 0;

  const server = http.createServer((req, res) => {
    requestCount += 1;
    const url = new URL(req.url, 'http://localhost');

    if (url.pathname === '/npm/all.zip') {
      res.setHeader('content-type', 'application/zip');
      res.end(zipBuffer);
      return;
    }

    if (url.pathname === '/npm/modified_id.csv') {
      if (req.headers['if-none-match'] === csvEtag) {
        res.statusCode = 304;
        res.end();
        return;
      }
      res.setHeader('etag', csvEtag);
      res.setHeader('last-modified', new Date(0).toUTCString());
      res.setHeader('content-type', 'text/csv');
      res.end(
        csvRows.map(r => `${r.modified},${r.id}`).join('\n') +
          (csvRows.length ? '\n' : ''),
      );
      return;
    }

    const idMatch = url.pathname.match(/^\/npm\/(.+)\.json$/);
    if (idMatch) {
      const record = recordsById.get(idMatch[1]);
      if (!record) {
        res.statusCode = 404;
        res.end('{}');
        return;
      }
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(record));
      return;
    }

    res.statusCode = 404;
    res.end('{}');
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const {port} = server.address();

  return {
    server,
    baseUrl: `http://127.0.0.1:${port}/npm/`,
    requestCount: () => requestCount,
    async setFixtureRecords(records) {
      zipBuffer = await buildZip(records);
    },
    setCsvRows(rows) {
      csvRows = rows;
    },
    setCsvEtag(etag) {
      csvEtag = etag;
    },
    setRecord(id, record) {
      recordsById.set(id, record);
    },
  };
}

// Fakes exactly the DynamoDBDocumentClient surface MaliciousPackageStore
// uses (Scan/Put/Delete/BatchWrite), backed by a plain Map, with
// failure-injection hooks for exercising the retry/all-or-nothing logic.
function makeFakeDynamoClient() {
  const table = new Map();
  const flags = {failNextBatchWrite: false};
  let callCount = 0;

  return {
    table,
    callCount: () => callCount,
    // Persistent, not single-shot -- each test constructs its own fresh
    // client, so there's no need to auto-reset, and a persistent failure is
    // what actually exercises _writeChunkWithRetry() exhausting its retries
    // (a single-shot failure would just succeed on the automatic retry,
    // masking the very behavior this is meant to test).
    failNextBatchWrite() {
      flags.failNextBatchWrite = true;
    },
    async send(command) {
      callCount += 1;

      if (command instanceof ScanCommand) {
        return {Items: Array.from(table.values())};
      }

      if (command instanceof GetCommand) {
        return {Item: table.get(command.input.Key.pk)};
      }

      if (command instanceof PutCommand) {
        table.set(command.input.Item.pk, command.input.Item);
        return {};
      }

      if (command instanceof DeleteCommand) {
        table.delete(command.input.Key.pk);
        return {};
      }

      if (command instanceof BatchWriteCommand) {
        if (flags.failNextBatchWrite)
          throw new Error('simulated BatchWriteCommand failure');
        const tableName = Object.keys(command.input.RequestItems)[0];
        for (const req of command.input.RequestItems[tableName]) {
          if (req.PutRequest)
            table.set(req.PutRequest.Item.pk, req.PutRequest.Item);
        }
        return {};
      }

      throw new Error(
        `fake dynamo client: unhandled command ${command.constructor.name}`,
      );
    },
  };
}

// Minimal fake ioredis surface (get/set/mget/scan/pipeline) -- just enough
// for a warm-start + bootstrap cycle. Full CRUD coverage for redis-store.js
// itself lives in test/smoke-storage-backends.js; this one only exists to
// prove osv.redis wins the storage-backend priority check below.
function makeFakeRedisClient() {
  const table = new Map();
  return {
    table,
    async get(key) {
      return table.has(key) ? table.get(key) : null;
    },
    async set(key, value) {
      table.set(key, value);
      return 'OK';
    },
    async mget(...keys) {
      return keys.map(k => (table.has(k) ? table.get(k) : null));
    },
    async scan(cursor) {
      if (cursor !== '0') return ['0', []];
      return ['0', Array.from(table.keys())];
    },
    pipeline() {
      const commands = [];
      const self = {
        set(key, value) {
          commands.push({key, value});
          return self;
        },
        async exec() {
          return commands.map(cmd => {
            table.set(cmd.key, cmd.value);
            return [null, 'OK'];
          });
        },
      };
      return self;
    },
    async quit() {},
  };
}

// warm-start (against an empty fake table on a fresh store) finds nothing to
// load, and autoSchedule:false means no background timer ever fires -- tests
// trigger the actual first bootstrap attempt deterministically themselves.
async function bootstrapStore(store) {
  await store.ready;
  await store.runSyncCycle();
}

function makeStore(config, docClient, optionsOverrides = {}) {
  _resetSharedStoreForTests(); // each test constructs its own store directly, not via the shared singleton
  return new MaliciousPackageStore(
    {enabled: true, dynamo: {tableName: 'test-table'}, ...config},
    {
      logger: NOOP_LOGGER,
      docClient,
      maxWriteRetries: 0, // no retry backoff sleeps in tests
      autoSchedule: false, // tests drive runSyncCycle() manually -- no background timer to race against
      ...optionsOverrides,
    },
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

  await check('enabled: false makes the whole subsystem inert', async () => {
    const osv = await startMockOsvServer();
    try {
      const store = makeStore(
        {enabled: false, baseUrl: osv.baseUrl},
        makeFakeDynamoClient(),
      );
      assert.equal(store.check('anything', '1.0.0'), null);
      assert.equal(store._timer, null);
      await new Promise(resolve => setTimeout(resolve, 50)); // give any accidental async work a chance to run
      assert.equal(
        osv.requestCount(),
        0,
        'no HTTP calls should have been made',
      );
    } finally {
      osv.server.close();
    }
  });

  await check(
    'bootstrap ingests non-withdrawn MAL/GHSA records with minimal fields; GHSA is inert without cve filters',
    async () => {
      const osv = await startMockOsvServer();
      const client = makeFakeDynamoClient();
      try {
        await osv.setFixtureRecords([
          makeOsvRecord({
            id: 'MAL-2025-1',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'evil-one',
          }),
          makeGhsaRecord({
            id: 'GHSA-xxxx-yyyy-zzzz',
            modified: '2025-01-02T00:00:00Z',
            packageName: 'unrelated-cve-pkg',
            severity: 'HIGH',
          }),
          makeOsvRecord({
            id: 'MAL-2025-2',
            modified: '2025-01-03T00:00:00Z',
            packageName: 'evil-two',
            withdrawn: true,
          }),
        ]);
        osv.setCsvRows([]);

        const store = makeStore({baseUrl: osv.baseUrl}, client);
        await bootstrapStore(store);

        assert.ok(
          store.check('evil-one', '1.0.0'),
          'the non-withdrawn MAL record should be ingested',
        );
        assert.equal(
          store.check('unrelated-cve-pkg', '1.0.0'),
          null,
          'a GHSA record is tracked but inert until osv.cve.severity/osv.cve.cwe is configured',
        );
        assert.equal(
          client.table.get('unrelated-cve-pkg')?.cves?.length,
          1,
          'the CVE data itself is still stored, just not blocking by default',
        );
        assert.equal(
          store.check('evil-two', '1.0.0'),
          null,
          'withdrawn records must not be ingested during bootstrap',
        );

        const stored = client.table.get('evil-one');
        assert.deepEqual(Object.keys(stored).sort(), [
          'malIds',
          'modified',
          'originCount',
          'pk',
          'ranges',
          'sources',
        ]);
        assert.deepEqual(stored.ranges, [{introduced: '0', fixed: null}]);
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'whole-package block (introduced: 0) matches every version; a bounded range matches only within it',
    async () => {
      const osv = await startMockOsvServer();
      try {
        await osv.setFixtureRecords([
          makeOsvRecord({
            id: 'MAL-2025-10',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'whole-pkg',
          }),
          makeOsvRecord({
            id: 'MAL-2025-11',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'ranged-pkg',
            introduced: '1.0.0',
            fixed: '2.0.0',
          }),
        ]);
        osv.setCsvRows([]);

        const store = makeStore({baseUrl: osv.baseUrl}, makeFakeDynamoClient());
        await bootstrapStore(store);

        assert.ok(store.check('whole-pkg', '0.0.1'));
        assert.ok(store.check('whole-pkg', '99.0.0'));
        assert.ok(store.check('ranged-pkg', '1.5.0'));
        assert.equal(store.check('ranged-pkg', '0.9.0'), null); // below the range
        assert.equal(store.check('ranged-pkg', '2.0.0'), null); // fixed is exclusive
        assert.equal(store.check('ranged-pkg', '3.0.0'), null); // above the range
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'second poll against an unchanged CSV short-circuits at 304 with zero DynamoDB calls',
    async () => {
      const osv = await startMockOsvServer();
      const client = makeFakeDynamoClient();
      try {
        await osv.setFixtureRecords([]);
        osv.setCsvRows([]);

        const store = makeStore({baseUrl: osv.baseUrl}, client);
        await bootstrapStore(store); // completes bootstrap, which does touch DynamoDB

        const callsAfterBootstrap = client.callCount();
        await store.runSyncCycle(); // steady-state now; CSV etag hasn't changed
        assert.equal(
          client.callCount(),
          callsAfterBootstrap,
          'a 304 poll must make zero further DynamoDB calls',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'an irrelevant (neither MAL- nor GHSA-) CSV row still advances the high-water-mark without any advisory write',
    async () => {
      const osv = await startMockOsvServer();
      const client = makeFakeDynamoClient();
      try {
        await osv.setFixtureRecords([]);
        osv.setCsvRows([]);
        const store = makeStore({baseUrl: osv.baseUrl}, client);
        await bootstrapStore(store);

        osv.setCsvEtag('etag-v2');
        // GSD- is a real, rare OSV id prefix (1 npm entry as of this session's
        // sample) that's neither MAL- nor GHSA- -- exactly the "irrelevant to
        // us" case this test means to exercise.
        osv.setCsvRows([
          {modified: '2030-01-01T00:00:00Z', id: 'GSD-nnnn-nnnn-nnnn'},
        ]);
        await store.runSyncCycle();

        assert.equal(store._lastSyncedModifiedId, '2030-01-01T00:00:00Z');
        assert.equal(store.check('anything', '1.0.0'), null); // nothing malicious was actually applied
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'an advisory changed since bootstrap is fetched individually and applied',
    async () => {
      const osv = await startMockOsvServer();
      const client = makeFakeDynamoClient();
      try {
        await osv.setFixtureRecords([]);
        osv.setCsvRows([]);
        const store = makeStore({baseUrl: osv.baseUrl}, client);
        await bootstrapStore(store);

        osv.setCsvEtag('etag-v2');
        osv.setCsvRows([{modified: '2030-01-01T00:00:00Z', id: 'MAL-2030-1'}]);
        osv.setRecord(
          'MAL-2030-1',
          makeOsvRecord({
            id: 'MAL-2030-1',
            modified: '2030-01-01T00:00:00Z',
            packageName: 'newly-flagged',
          }),
        );
        await store.runSyncCycle();

        assert.ok(store.check('newly-flagged', '1.0.0'));
        assert.ok(client.table.get('newly-flagged'));
        assert.equal(store._lastSyncedModifiedId, '2030-01-01T00:00:00Z');
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'incremental sync alerts (loud log + webhook) when the newly-applied delta matches a package already cached locally',
    async () => {
      const osv = await startMockOsvServer();
      const client = makeFakeDynamoClient();
      const receiver = await startWebhookReceiver();
      try {
        await osv.setFixtureRecords([]);
        osv.setCsvRows([]);
        const logger = makeCapturingLogger();
        const store = makeStore({baseUrl: osv.baseUrl}, client, {
          logger,
          webhookConfig: {
            url: `${receiver.url}/alert`,
            body: '{"pkg":"{{pkg}}","ver":"{{ver}}","malIds":"{{malIds}}"}',
          },
        });
        await bootstrapStore(store);

        const registryStorage = makeFakeRegistryStorage();
        registryStorage.setExisting('newly-flagged', {
          '1.0.0': {version: '1.0.0'},
          '2.0.0': {version: '2.0.0'}, // outside the advisory's range -- must not alert
        });
        store.attachRegistryStorage(registryStorage);

        osv.setCsvEtag('etag-v2');
        osv.setCsvRows([{modified: '2030-01-01T00:00:00Z', id: 'MAL-2030-1'}]);
        osv.setRecord(
          'MAL-2030-1',
          makeOsvRecord({
            id: 'MAL-2030-1',
            modified: '2030-01-01T00:00:00Z',
            packageName: 'newly-flagged',
            fixed: '1.5.0', // covers 1.0.0, not 2.0.0
          }),
        );
        await store.runSyncCycle();

        assert.equal(
          logger.calls.error.length,
          1,
          'exactly one cached version (1.0.0) should have triggered the alert',
        );
        const [fields, message] = logger.calls.error[0];
        assert.equal(fields.pkg, 'newly-flagged');
        assert.equal(fields.ver, '1.0.0');
        assert.match(message, /CACHED PACKAGE NOW FLAGGED/);

        await waitFor(() => receiver.requests.length > 0);
        assert.equal(receiver.requests.length, 1);
        const payload = JSON.parse(receiver.requests[0].body);
        assert.equal(payload.pkg, 'newly-flagged');
        assert.equal(payload.ver, '1.0.0');
        assert.equal(payload.malIds, 'MAL-2030-1');
      } finally {
        osv.server.close();
        await receiver.close();
      }
    },
  );

  await check(
    'bootstrap does not fire the retroactive alert, even for a package it flags that is already cached locally',
    async () => {
      const osv = await startMockOsvServer();
      const client = makeFakeDynamoClient();
      const receiver = await startWebhookReceiver();
      try {
        await osv.setFixtureRecords([
          makeOsvRecord({
            id: 'MAL-2025-99',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'already-cached',
          }),
        ]);
        osv.setCsvRows([]);
        const logger = makeCapturingLogger();
        const registryStorage = makeFakeRegistryStorage();
        registryStorage.setExisting('already-cached', {
          '1.0.0': {version: '1.0.0'},
        });

        const store = makeStore({baseUrl: osv.baseUrl}, client, {
          logger,
          webhookConfig: {url: `${receiver.url}/alert`},
        });
        store.attachRegistryStorage(registryStorage); // attached before bootstrap runs

        await bootstrapStore(store);

        assert.ok(
          store.check('already-cached', '1.0.0'),
          'bootstrap should still apply the block itself',
        );
        assert.equal(
          logger.calls.error.length,
          0,
          'bootstrap must not fire the retroactive alert -- it is a one-time historical load, not "new" OSV data',
        );
        await new Promise(resolve => setTimeout(resolve, 50)); // give any accidental async webhook a chance to arrive
        assert.equal(receiver.requests.length, 0);
      } finally {
        osv.server.close();
        await receiver.close();
      }
    },
  );

  await check('withdrawal removes the right item', async () => {
    const osv = await startMockOsvServer();
    const client = makeFakeDynamoClient();
    try {
      await osv.setFixtureRecords([
        makeOsvRecord({
          id: 'MAL-2025-50',
          modified: '2025-01-01T00:00:00Z',
          packageName: 'soon-cleared',
        }),
      ]);
      osv.setCsvRows([]);
      const store = makeStore({baseUrl: osv.baseUrl}, client);
      await bootstrapStore(store);
      assert.ok(store.check('soon-cleared', '1.0.0'));

      osv.setCsvEtag('etag-v2');
      osv.setCsvRows([{modified: '2030-01-01T00:00:00Z', id: 'MAL-2025-50'}]);
      osv.setRecord(
        'MAL-2025-50',
        makeOsvRecord({
          id: 'MAL-2025-50',
          modified: '2030-01-01T00:00:00Z',
          packageName: 'soon-cleared',
          withdrawn: true,
        }),
      );
      await store.runSyncCycle();

      assert.equal(store.check('soon-cleared', '1.0.0'), null);
      assert.equal(client.table.get('soon-cleared'), undefined);
    } finally {
      osv.server.close();
    }
  });

  await check(
    'a DynamoDB write failure mid-cycle leaves the high-water-mark/etag untouched (retry-safe)',
    async () => {
      const osv = await startMockOsvServer();
      const client = makeFakeDynamoClient();
      try {
        await osv.setFixtureRecords([]);
        osv.setCsvRows([]);
        const store = makeStore({baseUrl: osv.baseUrl}, client);
        await bootstrapStore(store);
        const watermarkBefore = store._lastSyncedModifiedId;
        const etagBefore = store._csvEtag;

        osv.setCsvEtag('etag-v2');
        osv.setCsvRows([{modified: '2030-01-01T00:00:00Z', id: 'MAL-2030-99'}]);
        osv.setRecord(
          'MAL-2030-99',
          makeOsvRecord({
            id: 'MAL-2030-99',
            modified: '2030-01-01T00:00:00Z',
            packageName: 'flaky-write',
          }),
        );
        // _writeChunkWithRetry always issues a BatchWriteCommand, even for a
        // single item, so this is the one failure mode to inject here.
        client.failNextBatchWrite();

        await store.runSyncCycle();

        assert.equal(
          store._lastSyncedModifiedId,
          watermarkBefore,
          'watermark must not advance when a write failed this cycle',
        );
        assert.equal(
          store._csvEtag,
          etagBefore,
          'etag must not advance when a write failed this cycle',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  // --- MAL confidence filters (osv.malware.minOrigin / osv.malware.sources) ---

  await check(
    'MAL origin count: a zero-origin record is not blocked by default, but is at malware.minOrigin: 0',
    async () => {
      const osv = await startMockOsvServer();
      try {
        await osv.setFixtureRecords([
          makeOsvRecord({
            id: 'MAL-2025-100',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'zero-origin-pkg',
            origins: [],
          }),
        ]);
        osv.setCsvRows([]);

        const defaultStore = makeStore(
          {baseUrl: osv.baseUrl},
          makeFakeDynamoClient(),
        );
        await bootstrapStore(defaultStore);
        assert.equal(
          defaultStore.check('zero-origin-pkg', '1.0.0'),
          null,
          'default malware.minOrigin: 1 should not block a zero-origin record',
        );

        const permissiveStore = makeStore(
          {baseUrl: osv.baseUrl, malware: {minOrigin: 0}},
          makeFakeDynamoClient(),
        );
        await bootstrapStore(permissiveStore);
        assert.ok(
          permissiveStore.check('zero-origin-pkg', '1.0.0'),
          'malware.minOrigin: 0 should block a zero-origin record',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'MAL source filter: malware.sources only blocks when an origin source matches',
    async () => {
      const osv = await startMockOsvServer();
      try {
        await osv.setFixtureRecords([
          makeOsvRecord({
            id: 'MAL-2025-101',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'checkmarx-pkg',
            origins: [{source: 'checkmarx'}],
          }),
        ]);
        osv.setCsvRows([]);

        const nonMatching = makeStore(
          {baseUrl: osv.baseUrl, malware: {sources: ['reversing-labs']}},
          makeFakeDynamoClient(),
        );
        await bootstrapStore(nonMatching);
        assert.equal(
          nonMatching.check('checkmarx-pkg', '1.0.0'),
          null,
          'a source not in malware.sources should not block',
        );

        const matching = makeStore(
          {baseUrl: osv.baseUrl, malware: {sources: ['checkmarx']}},
          makeFakeDynamoClient(),
        );
        await bootstrapStore(matching);
        assert.ok(
          matching.check('checkmarx-pkg', '1.0.0'),
          'a source in malware.sources should block',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  // --- CVE (GHSA) blocking (osv.cve.severity / osv.cve.cwe) ---

  await check(
    'CVE severity filter blocks only a configured severity',
    async () => {
      const osv = await startMockOsvServer();
      try {
        await osv.setFixtureRecords([
          makeGhsaRecord({
            id: 'GHSA-1111-1111-1111',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'high-cve-pkg',
            severity: 'HIGH',
            cweIds: ['CWE-79'],
            cveId: 'CVE-2025-1',
          }),
        ]);
        osv.setCsvRows([]);

        const active = makeStore(
          {baseUrl: osv.baseUrl, cve: {severity: ['HIGH', 'CRITICAL']}},
          makeFakeDynamoClient(),
        );
        await bootstrapStore(active);
        const hit = active.check('high-cve-pkg', '1.0.0');
        assert.ok(hit);
        assert.equal(hit.type, 'cve');
        assert.equal(hit.cveId, 'CVE-2025-1');
        assert.equal(hit.severity, 'HIGH');

        const nonMatching = makeStore(
          {baseUrl: osv.baseUrl, cve: {severity: ['LOW']}},
          makeFakeDynamoClient(),
        );
        await bootstrapStore(nonMatching);
        assert.equal(
          nonMatching.check('high-cve-pkg', '1.0.0'),
          null,
          'HIGH severity should not match a LOW-only filter',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'CVE bare CWE entry in osv.cve.cwe blocks at any severity',
    async () => {
      const osv = await startMockOsvServer();
      try {
        await osv.setFixtureRecords([
          makeGhsaRecord({
            id: 'GHSA-2222-2222-2222',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'low-cwe-pkg',
            severity: 'LOW',
            cweIds: ['CWE-506'],
          }),
        ]);
        osv.setCsvRows([]);

        const store = makeStore(
          {baseUrl: osv.baseUrl, cve: {cwe: ['CWE-506']}},
          makeFakeDynamoClient(),
        );
        await bootstrapStore(store);
        assert.ok(
          store.check('low-cwe-pkg', '1.0.0'),
          'a bare CWE entry should block regardless of severity',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    "a CWE's own severity list in osv.cve.cwe overrides the global osv.cve.severity for that CWE",
    async () => {
      const osv = await startMockOsvServer();
      try {
        await osv.setFixtureRecords([
          makeGhsaRecord({
            id: 'GHSA-3333-3333-3333',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'override-pkg',
            severity: 'MODERATE',
            cweIds: ['CWE-79'],
          }),
        ]);
        osv.setCsvRows([]);

        // Global wants CRITICAL only, but CWE-79's own list includes MODERATE -- should still block.
        const wideOverride = makeStore(
          {
            baseUrl: osv.baseUrl,
            cve: {
              severity: ['CRITICAL'],
              cwe: [{'CWE-79': ['LOW', 'MODERATE']}],
            },
          },
          makeFakeDynamoClient(),
        );
        await bootstrapStore(wideOverride);
        assert.ok(
          wideOverride.check('override-pkg', '1.0.0'),
          "CWE-79's own severity list should override the global list",
        );

        // Same CWE, but the record's actual severity (MODERATE) isn't in a
        // narrower override list -- should not block, and the global list
        // (CRITICAL only) doesn't rescue it either.
        const narrowOverride = makeStore(
          {
            baseUrl: osv.baseUrl,
            cve: {severity: ['CRITICAL'], cwe: [{'CWE-79': ['HIGH']}]},
          },
          makeFakeDynamoClient(),
        );
        await bootstrapStore(narrowOverride);
        assert.equal(
          narrowOverride.check('override-pkg', '1.0.0'),
          null,
          'MODERATE should not match a HIGH-only override for CWE-79',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  // --- Merging MAL and CVE data for the same package (bootstrap + incremental) ---

  await check(
    'bootstrap merges a MAL record and a GHSA record for the same package without clobbering either',
    async () => {
      const osv = await startMockOsvServer();
      const client = makeFakeDynamoClient();
      try {
        await osv.setFixtureRecords([
          makeOsvRecord({
            id: 'MAL-2025-200',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'dual-pkg',
          }),
          makeGhsaRecord({
            id: 'GHSA-4444-4444-4444',
            modified: '2025-01-02T00:00:00Z',
            packageName: 'dual-pkg',
            severity: 'CRITICAL',
            cweIds: ['CWE-79'],
          }),
        ]);
        osv.setCsvRows([]);

        const store = makeStore(
          {baseUrl: osv.baseUrl, cve: {severity: ['CRITICAL']}},
          client,
        );
        await bootstrapStore(store);

        const hit = store.check('dual-pkg', '1.0.0');
        assert.ok(hit);
        assert.equal(
          hit.type,
          'mal',
          'the MAL dimension is checked first and already matches unconditionally',
        );

        const stored = client.table.get('dual-pkg');
        assert.ok(
          stored.malIds,
          'MAL fields must survive being merged with the GHSA record',
        );
        assert.equal(
          stored.cves?.length,
          1,
          'CVE fields must survive being merged with the MAL record',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'incremental sync preserves the other dimension when only one of MAL/CVE changes',
    async () => {
      const osv = await startMockOsvServer();
      const client = makeFakeDynamoClient();
      try {
        await osv.setFixtureRecords([
          makeOsvRecord({
            id: 'MAL-2025-300',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'incremental-pkg',
          }),
        ]);
        osv.setCsvRows([]);
        const store = makeStore(
          {baseUrl: osv.baseUrl, cve: {severity: ['HIGH']}},
          client,
        );
        await bootstrapStore(store);
        assert.ok(store.check('incremental-pkg', '1.0.0'));

        osv.setCsvEtag('etag-v2');
        osv.setCsvRows([
          {modified: '2030-01-01T00:00:00Z', id: 'GHSA-5555-5555-5555'},
        ]);
        osv.setRecord(
          'GHSA-5555-5555-5555',
          makeGhsaRecord({
            id: 'GHSA-5555-5555-5555',
            modified: '2030-01-01T00:00:00Z',
            packageName: 'incremental-pkg',
            severity: 'HIGH',
            cweIds: ['CWE-79'],
          }),
        );
        await store.runSyncCycle();

        const stored = client.table.get('incremental-pkg');
        assert.ok(
          stored.malIds,
          'the earlier MAL fields must survive an incremental CVE-only update',
        );
        assert.equal(
          stored.cves?.length,
          1,
          'the new CVE entry must be applied',
        );
        assert.ok(store.check('incremental-pkg', '1.0.0'));
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'withdrawal of a GHSA id only removes the CVE dimension, leaving MAL intact',
    async () => {
      const osv = await startMockOsvServer();
      const client = makeFakeDynamoClient();
      try {
        await osv.setFixtureRecords([
          makeOsvRecord({
            id: 'MAL-2025-400',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'mixed-pkg',
          }),
          makeGhsaRecord({
            id: 'GHSA-6666-6666-6666',
            modified: '2025-01-02T00:00:00Z',
            packageName: 'mixed-pkg',
            severity: 'HIGH',
            cweIds: ['CWE-79'],
          }),
        ]);
        osv.setCsvRows([]);
        const store = makeStore(
          {baseUrl: osv.baseUrl, cve: {severity: ['HIGH']}},
          client,
        );
        await bootstrapStore(store);
        assert.ok(client.table.get('mixed-pkg').cves);
        assert.ok(client.table.get('mixed-pkg').malIds);

        osv.setCsvEtag('etag-v2');
        osv.setCsvRows([
          {modified: '2030-01-01T00:00:00Z', id: 'GHSA-6666-6666-6666'},
        ]);
        osv.setRecord(
          'GHSA-6666-6666-6666',
          makeGhsaRecord({
            id: 'GHSA-6666-6666-6666',
            modified: '2030-01-01T00:00:00Z',
            packageName: 'mixed-pkg',
            withdrawn: true,
          }),
        );
        await store.runSyncCycle();

        const stored = client.table.get('mixed-pkg');
        assert.equal(
          stored.cves,
          undefined,
          'the withdrawn CVE entry should be removed',
        );
        assert.ok(
          stored.malIds,
          'the MAL dimension should be untouched by a CVE withdrawal',
        );
        assert.ok(
          store.check('mixed-pkg', '1.0.0'),
          'still blocked via the surviving MAL dimension',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'withdrawal of the only MAL id, with no CVEs on the item, deletes the whole item',
    async () => {
      const osv = await startMockOsvServer();
      const client = makeFakeDynamoClient();
      try {
        await osv.setFixtureRecords([
          makeOsvRecord({
            id: 'MAL-2025-401',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'mal-only-pkg',
          }),
        ]);
        osv.setCsvRows([]);
        const store = makeStore({baseUrl: osv.baseUrl}, client);
        await bootstrapStore(store);
        assert.ok(store.check('mal-only-pkg', '1.0.0'));

        osv.setCsvEtag('etag-v2');
        osv.setCsvRows([
          {modified: '2030-01-01T00:00:00Z', id: 'MAL-2025-401'},
        ]);
        osv.setRecord(
          'MAL-2025-401',
          makeOsvRecord({
            id: 'MAL-2025-401',
            modified: '2030-01-01T00:00:00Z',
            packageName: 'mal-only-pkg',
            withdrawn: true,
          }),
        );
        await store.runSyncCycle();

        assert.equal(store.check('mal-only-pkg', '1.0.0'), null);
        assert.equal(
          client.table.get('mal-only-pkg'),
          undefined,
          'the whole item should be deleted once both dimensions are empty',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  // --- Storage backend auto-selection (osv.redis / osv.dynamo / osv.filesystem) ---
  // DynamoDB (picked when osv.dynamo is configured) already has full
  // coverage above via every prior test in this file; this proves the same
  // generalized sync engine works correctly through a second, real backend
  // selected by configuring osv.filesystem instead -- the two backends' own
  // CRUD contracts are covered directly in test/smoke-storage-backends.js.

  await check(
    'end-to-end bootstrap + incremental withdrawal works through the filesystem storage backend too',
    async () => {
      const osv = await startMockOsvServer();
      const dir = await fs.mkdtemp(
        path.join(os.tmpdir(), 'security-filter-fs-backend-test-'),
      );
      try {
        await osv.setFixtureRecords([
          makeOsvRecord({
            id: 'MAL-2025-500',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'fs-backend-pkg',
          }),
        ]);
        osv.setCsvRows([]);

        _resetSharedStoreForTests();
        const store = new MaliciousPackageStore(
          {enabled: true, filesystem: {path: dir}, baseUrl: osv.baseUrl},
          {logger: NOOP_LOGGER, maxWriteRetries: 0, autoSchedule: false},
        );
        await bootstrapStore(store);
        assert.ok(
          store.check('fs-backend-pkg', '1.0.0'),
          'bootstrap through the filesystem backend should block the fixture package',
        );

        // Confirm it's actually durable on disk, not just in the in-memory Map.
        const filesOnDisk = await fs.readdir(dir);
        assert.ok(
          filesOnDisk.some(name =>
            name.includes(encodeURIComponent('fs-backend-pkg')),
          ),
        );

        // Incremental withdrawal should behave identically to the DynamoDB-backed tests above.
        osv.setCsvEtag('etag-v2');
        osv.setCsvRows([
          {modified: '2030-01-01T00:00:00Z', id: 'MAL-2025-500'},
        ]);
        osv.setRecord(
          'MAL-2025-500',
          makeOsvRecord({
            id: 'MAL-2025-500',
            modified: '2030-01-01T00:00:00Z',
            packageName: 'fs-backend-pkg',
            withdrawn: true,
          }),
        );
        await store.runSyncCycle();
        assert.equal(store.check('fs-backend-pkg', '1.0.0'), null);
      } finally {
        osv.server.close();
        await fs.rm(dir, {recursive: true, force: true});
      }
    },
  );

  await check(
    'osv.redis wins over osv.dynamo when both are configured',
    async () => {
      const osv = await startMockOsvServer();
      const redisClient = makeFakeRedisClient();
      // A docClient that throws on any command -- if the store wrongly picked
      // dynamo instead of redis, this makes that failure loud instead of
      // silently also writing to a second backend.
      const poisonDocClient = {
        send: () =>
          Promise.reject(
            new Error('dynamo must not be used when osv.redis is configured'),
          ),
      };
      try {
        await osv.setFixtureRecords([
          makeOsvRecord({
            id: 'MAL-2025-700',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'redis-priority-pkg',
          }),
        ]);
        osv.setCsvRows([]);

        _resetSharedStoreForTests();
        const store = new MaliciousPackageStore(
          {
            enabled: true,
            redis: {url: 'redis://localhost:6379'},
            dynamo: {tableName: 'test-table'},
            baseUrl: osv.baseUrl,
          },
          {
            logger: NOOP_LOGGER,
            redisClient,
            docClient: poisonDocClient,
            maxWriteRetries: 0,
            autoSchedule: false,
          },
        );
        assert.equal(store.storageKind, 'redis');
        await bootstrapStore(store);

        assert.ok(
          store.check('redis-priority-pkg', '1.0.0'),
          'should have synced through the redis backend',
        );
        assert.ok(
          redisClient.table.get('redis-priority-pkg'),
          'the fake redis table should have received the write',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'osv.dynamo wins over osv.filesystem when both are configured',
    async () => {
      const osv = await startMockOsvServer();
      const client = makeFakeDynamoClient();
      const dir = await fs.mkdtemp(
        path.join(os.tmpdir(), 'security-filter-priority-test-'),
      );
      try {
        await osv.setFixtureRecords([
          makeOsvRecord({
            id: 'MAL-2025-600',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'priority-pkg',
          }),
        ]);
        osv.setCsvRows([]);

        _resetSharedStoreForTests();
        const store = new MaliciousPackageStore(
          {
            enabled: true,
            dynamo: {tableName: 'test-table'},
            filesystem: {path: dir},
            baseUrl: osv.baseUrl,
          },
          {
            logger: NOOP_LOGGER,
            docClient: client,
            maxWriteRetries: 0,
            autoSchedule: false,
          },
        );
        assert.equal(store.storageKind, 'dynamo');
        await bootstrapStore(store);

        assert.ok(
          store.check('priority-pkg', '1.0.0'),
          'should have synced through the dynamo backend',
        );
        assert.ok(
          client.table.get('priority-pkg'),
          'the fake dynamo table should have received the write',
        );
        assert.deepEqual(
          await fs.readdir(dir),
          [],
          'osv.filesystem must be ignored when osv.dynamo is also configured',
        );
      } finally {
        osv.server.close();
        await fs.rm(dir, {recursive: true, force: true});
      }
    },
  );

  await check(
    'osv.enabled: true with no backend configured fails loud at construction',
    () => {
      _resetSharedStoreForTests();
      assert.throws(
        () =>
          new MaliciousPackageStore(
            {enabled: true},
            {logger: NOOP_LOGGER, autoSchedule: false},
          ),
        /osv\.redis \/ osv\.dynamo \/ osv\.filesystem/,
      );
    },
  );

  // --- DynamoDB keyPrefix (dynamodb-store.js) ---

  await check(
    'dynamodb-store: keyPrefix namespaces the stored pk but round-trips the original pk back to the caller',
    async () => {
      const client = makeFakeDynamoClient();
      const store = createDynamoDbStore(
        {tableName: 'test-table', keyPrefix: 'osv-'},
        {docClient: client, logger: NOOP_LOGGER, maxWriteRetries: 0},
      );

      await store.putItem({pk: 'left-pad', ranges: []});
      assert.ok(
        client.table.has('osv-left-pad'),
        'the underlying table row must carry the prefix',
      );
      assert.ok(!client.table.has('left-pad'));
      assert.deepEqual(await store.getItem('left-pad'), {
        pk: 'left-pad',
        ranges: [],
      });

      const unwritten = await store.putItems([{pk: 'pkg-a', ranges: []}]);
      assert.deepEqual(unwritten, []);
      assert.ok(client.table.has('osv-pkg-a'));

      const scanned = await store.scanAll();
      assert.deepEqual(
        scanned.map(i => i.pk).sort(),
        ['left-pad', 'pkg-a'],
        'scanAll must strip the prefix back off',
      );

      await store.deleteItem('left-pad');
      assert.ok(!client.table.has('osv-left-pad'));
    },
  );

  console.log(`\n${passed} check(s) passed.`);
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
