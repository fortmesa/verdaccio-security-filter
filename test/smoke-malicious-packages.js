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
const zlib = require('node:zlib');
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
const osvClient = require('../osv-client.js');

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

// Minimal Storage stand-in -- same shape test/smoke.js and
// test/smoke-webhook.js use, just under the name this file's own tests
// reach for. The retroactive check reads raw local metadata through
// localStorage.getPackageMetadata(); getPackage() is Verdaccio's filtered
// read, and `filteredView` gives it a different answer to prove the check
// never uses it.
function makeFakeRegistryStorage() {
  const existingByName = new Map();
  const filteredByName = new Map();
  return {
    setExisting(name, versions) {
      existingByName.set(name, {versions});
    },
    filteredView(name, versions) {
      filteredByName.set(name, {versions});
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
  lastAffected = null,
  lastKnownAffectedVersionRange = null,
  withdrawn = false,
  severity = 'HIGH',
  cweIds = ['CWE-79'],
  cveId,
  cvss3Vector = null,
  cvss4Vector = null,
}) {
  const events = [{introduced}];
  // The OSV schema forbids both appearing on the same range -- callers pass
  // at most one of fixed/lastAffected, same as a real record ever would.
  if (fixed) events.push({fixed});
  if (lastAffected) events.push({last_affected: lastAffected});
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
        // Real GHSA records (e.g. xlsx's GHSA-5pgg-2g8v-p4x9) carry this
        // per-affected-entry, non-standard field when there's no structured
        // fixed/last_affected event at all -- see osv-client.js's
        // parseLastKnownAffectedVersionRange().
        ...(lastKnownAffectedVersionRange
          ? {
              database_specific: {
                last_known_affected_version_range:
                  lastKnownAffectedVersionRange,
              },
            }
          : {}),
      },
    ],
    // Real records carry this at the record's top level, independent of
    // database_specific -- see osv-client.js's computeCvssScores().
    ...(cvss3Vector || cvss4Vector
      ? {
          severity: [
            ...(cvss3Vector ? [{type: 'CVSS_V3', score: cvss3Vector}] : []),
            ...(cvss4Vector ? [{type: 'CVSS_V4', score: cvss4Vector}] : []),
          ],
        }
      : {}),
    database_specific: {severity, cwe_ids: cweIds},
  };
}

// Writes a zip of stored (uncompressed) entries, which is all the fixture
// feed needs: local headers, a central directory and its end record, with
// zlib.crc32 for the checksums.
function buildZip(records) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const record of records) {
    const name = Buffer.from(`npm/${record.id}.json`);
    const data = Buffer.from(JSON.stringify(record));
    const crc = zlib.crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // version made by
    central.writeUInt16LE(20, 6); // version needed
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, name, data);
    centrals.push(central, name);
    offset += local.length + name.length + data.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(records.length, 8);
  end.writeUInt16LE(records.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Promise.resolve(Buffer.concat([...locals, directory, end]));
}

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
          'mals',
          'modified',
          'pk',
        ]);
        assert.equal(stored.mals.length, 1);
        assert.deepEqual(Object.keys(stored.mals[0]).sort(), [
          'id',
          'originCount',
          'sources',
          'vulnerableVersions',
        ]);
        assert.equal(
          stored.mals[0].vulnerableVersions,
          '*',
          'a whole-package block (introduced: "0", no fixed/lastAffected) is the "*" range',
        );
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
    'second poll against an unchanged CSV short-circuits at 304 with only the one version-check DynamoDB call',
    async () => {
      const osv = await startMockOsvServer();
      const client = makeFakeDynamoClient();
      try {
        await osv.setFixtureRecords([]);
        osv.setCsvRows([]);

        const store = makeStore({baseUrl: osv.baseUrl}, client);
        await bootstrapStore(store); // completes bootstrap, which does touch DynamoDB
        // Bootstrap stores no CSV etag (its watermark is the zip's own), so
        // the first incremental cycle reads the CSV in full and records it.
        await store.runSyncCycle();

        const callsAfterBootstrap = client.callCount();
        await store.runSyncCycle(); // steady-state now; CSV etag hasn't changed
        assert.equal(
          client.callCount(),
          callsAfterBootstrap + 1,
          'a 304 poll must make exactly one DynamoDB call -- the once-per-cycle version check -- and nothing further',
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
          logger.calls.fatal.length,
          1,
          'exactly one cached version (1.0.0) should have triggered the alert',
        );
        const [fields, message] = logger.calls.fatal[0];
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
          logger.calls.fatal.length,
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
        assert.equal(
          hit.severity,
          'high',
          'severity is normalized to lowercase at extraction, regardless of the uppercase fixture/config casing used above',
        );

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
    'osv.cve.severity/osv.cve.cwe accept lowercase config values too -- both cases are forced to the same lowercase form, so neither errors and both match the same (uppercase-in-OSV) data',
    async () => {
      const osv = await startMockOsvServer();
      try {
        await osv.setFixtureRecords([
          makeGhsaRecord({
            id: 'GHSA-8888-8888-8888',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'lowercase-cfg-pkg',
            severity: 'HIGH', // real OSV feed data is always uppercase
            cweIds: ['CWE-79'],
          }),
        ]);
        osv.setCsvRows([]);

        const lowercaseCfg = makeStore(
          {
            baseUrl: osv.baseUrl,
            cve: {
              severity: ['high', 'critical'],
              cwe: [{'CWE-79': ['high']}],
            },
          },
          makeFakeDynamoClient(),
        );
        await bootstrapStore(lowercaseCfg);
        assert.ok(
          lowercaseCfg.check('lowercase-cfg-pkg', '1.0.0'),
          'lowercase config must match real uppercase-in-OSV data without a config error',
        );

        const uppercaseCfg = makeStore(
          {baseUrl: osv.baseUrl, cve: {severity: ['HIGH']}},
          makeFakeDynamoClient(),
        );
        await bootstrapStore(uppercaseCfg);
        assert.ok(
          uppercaseCfg.check('lowercase-cfg-pkg', '1.0.0'),
          'uppercase config (matching the documented examples) must keep working exactly as before',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'CVE last_affected event blocks up to and including that version, unlike fixed which is exclusive',
    async () => {
      const osv = await startMockOsvServer();
      try {
        await osv.setFixtureRecords([
          makeGhsaRecord({
            id: 'GHSA-3333-3333-3333',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'last-affected-pkg',
            severity: 'HIGH',
            cweIds: ['CWE-79'],
            cveId: 'CVE-2025-2',
            lastAffected: '1.2.3',
          }),
        ]);
        osv.setCsvRows([]);

        const store = makeStore(
          {baseUrl: osv.baseUrl, cve: {severity: ['HIGH', 'CRITICAL']}},
          makeFakeDynamoClient(),
        );
        await bootstrapStore(store);

        assert.ok(
          store.check('last-affected-pkg', '1.2.3'),
          'last_affected is inclusive -- the last_affected version itself is still vulnerable',
        );
        assert.ok(store.check('last-affected-pkg', '1.0.0'));
        assert.equal(
          store.check('last-affected-pkg', '1.2.4'),
          null,
          'the version immediately above last_affected should be unaffected',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'CVE with no structured fixed/last_affected falls back to the free-text last_known_affected_version_range override (xlsx-shaped)',
    async () => {
      const osv = await startMockOsvServer();
      try {
        await osv.setFixtureRecords([
          makeGhsaRecord({
            id: 'GHSA-5pgg-2g8v-p4x9',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'xlsx-shaped-pkg',
            severity: 'HIGH',
            cweIds: ['CWE-1333'],
            lastKnownAffectedVersionRange: '< 0.20.2',
          }),
        ]);
        osv.setCsvRows([]);

        const store = makeStore(
          {baseUrl: osv.baseUrl, cve: {severity: ['HIGH', 'CRITICAL']}},
          makeFakeDynamoClient(),
        );
        await bootstrapStore(store);

        assert.ok(
          store.check('xlsx-shaped-pkg', '0.20.1'),
          'the free-text override should recover a real fixed boundary',
        );
        assert.equal(
          store.check('xlsx-shaped-pkg', '0.20.2'),
          null,
          '"<" is exclusive, same as a structured fixed event',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'CVE with no structured fixed/last_affected and an unparseable override stays open (fails closed, unchanged from before the fallback existed)',
    async () => {
      const osv = await startMockOsvServer();
      try {
        await osv.setFixtureRecords([
          makeGhsaRecord({
            id: 'GHSA-6666-6666-6666',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'garbage-override-pkg',
            severity: 'HIGH',
            cweIds: ['CWE-1333'],
            lastKnownAffectedVersionRange: '>=1.0.0 <2.0.0 || >=3.0.0',
          }),
        ]);
        osv.setCsvRows([]);

        const store = makeStore(
          {baseUrl: osv.baseUrl, cve: {severity: ['HIGH', 'CRITICAL']}},
          makeFakeDynamoClient(),
        );
        await bootstrapStore(store);

        assert.ok(
          store.check('garbage-override-pkg', '99.0.0'),
          'a multi-clause/unparseable override must not silently narrow the range -- it stays open',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'CVE cvss3Min blocks at or above the configured threshold, independent of severity/cwe',
    async () => {
      const osv = await startMockOsvServer();
      try {
        // Real vector from lodash's GHSA-35jh-r3h4-6jhm -- verified against
        // the live npm registry's own reported score of 7.2.
        await osv.setFixtureRecords([
          makeGhsaRecord({
            id: 'GHSA-4444-4444-4444',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'cvss3-pkg',
            cvss3Vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
          }),
        ]);
        osv.setCsvRows([]);

        const blocking = makeStore(
          {baseUrl: osv.baseUrl, cve: {cvss3Min: 7.0}},
          makeFakeDynamoClient(),
        );
        await bootstrapStore(blocking);
        assert.ok(
          blocking.check('cvss3-pkg', '1.0.0'),
          'a score of 7.2 should match a minimum of 7.0',
        );

        const nonBlocking = makeStore(
          {baseUrl: osv.baseUrl, cve: {cvss3Min: 7.3}},
          makeFakeDynamoClient(),
        );
        await bootstrapStore(nonBlocking);
        assert.equal(
          nonBlocking.check('cvss3-pkg', '1.0.0'),
          null,
          'a score of 7.2 should not match a minimum of 7.3',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'CVE cvss4Min blocks independently of cvss3Min -- configuring one never triggers via the other',
    async () => {
      const osv = await startMockOsvServer();
      try {
        // Real vector shape verified against ae-cvss-calculator directly
        // (base score 8.8).
        await osv.setFixtureRecords([
          makeGhsaRecord({
            id: 'GHSA-5555-5555-5555',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'cvss4-pkg',
            cvss4Vector:
              'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N',
          }),
        ]);
        osv.setCsvRows([]);

        const cvss4Only = makeStore(
          {baseUrl: osv.baseUrl, cve: {cvss4Min: 8.0}},
          makeFakeDynamoClient(),
        );
        await bootstrapStore(cvss4Only);
        assert.ok(
          cvss4Only.check('cvss4-pkg', '1.0.0'),
          'a v4 score of 8.8 should match a cvss4Min of 8.0',
        );

        const cvss3Only = makeStore(
          {baseUrl: osv.baseUrl, cve: {cvss3Min: 1.0}},
          makeFakeDynamoClient(),
        );
        await bootstrapStore(cvss3Only);
        assert.equal(
          cvss3Only.check('cvss4-pkg', '1.0.0'),
          null,
          'a record with no v3 score must never match via cvss3Min, even a permissive one',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'osv.cve.cvss3Min/cvss4Min out of the 0-10 range fails loud at construction',
    async () => {
      assert.throws(
        () =>
          makeStore(
            {baseUrl: 'http://unused', cve: {cvss3Min: 11}},
            makeFakeDynamoClient(),
          ),
        /osv\.cve\.cvss3Min must be a number between 0 and 10/,
      );
      assert.throws(
        () =>
          makeStore(
            {baseUrl: 'http://unused', cve: {cvss4Min: -1}},
            makeFakeDynamoClient(),
          ),
        /osv\.cve\.cvss4Min must be a number between 0 and 10/,
      );
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
          stored.mals?.length,
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
          stored.mals?.length,
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
        assert.ok(client.table.get('mixed-pkg').mals?.length);

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
          stored.mals?.length,
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

  await check(
    'a stored extractionSchemaVersion mismatch (or none at all) forces a full re-bootstrap instead of loading stale data',
    async () => {
      const client = makeFakeDynamoClient();
      // Simulate a table an older code version already populated: sync
      // state with no extractionSchemaVersion field at all, and an item
      // shaped the way pre-fix code would have written it (uppercase
      // severity, no cvss3Score/cvss4Score) -- exactly the staleness this
      // mechanism exists to catch.
      client.table.set('__sync_state__', {
        pk: '__sync_state__',
        bootstrapCompletedAt: '2020-01-01T00:00:00Z',
        lastSyncedModifiedId: '2020-01-01T00:00:00Z',
        csvEtag: 'stale-etag',
        csvLastModified: 'stale-last-modified',
      });
      client.table.set('stale-pkg', {
        pk: 'stale-pkg',
        cves: [
          {
            id: 'GHSA-old',
            severity: 'HIGH', // pre-fix code stored this uppercase
            cweIds: [],
            ranges: [{introduced: '0', fixed: null}],
          },
        ],
      });

      const osv = await startMockOsvServer();
      try {
        await osv.setFixtureRecords([
          makeGhsaRecord({
            id: 'GHSA-fresh-1',
            modified: '2025-06-01T00:00:00Z',
            packageName: 'fresh-pkg',
            severity: 'CRITICAL',
            cweIds: ['CWE-1321'],
          }),
        ]);
        osv.setCsvRows([]);

        const store = makeStore(
          {baseUrl: osv.baseUrl, cve: {severity: ['CRITICAL']}},
          client,
        );
        await store.ready; // warm-start alone -- should discard the stale table entirely

        assert.equal(
          store.check('stale-pkg', '1.0.0'),
          null,
          'data written under an old/missing extractionSchemaVersion must not be loaded into memory',
        );

        await store.runSyncCycle(); // must run a full bootstrap, not an incremental sync
        assert.ok(
          store.check('fresh-pkg', '1.0.0'),
          'the forced re-bootstrap should have picked up the fresh OSV fixture data',
        );

        const stateItem = client.table.get('__sync_state__');
        assert.equal(
          stateItem.extractionSchemaVersion,
          osvClient.EXTRACTION_SCHEMA_VERSION,
          'the fresh bootstrap should stamp the current schema version going forward',
        );
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'a stored extractionSchemaVersion NEWER than this code refuses to start, rather than serving degraded',
    async () => {
      const client = makeFakeDynamoClient();
      client.table.set('__sync_state__', {
        pk: '__sync_state__',
        bootstrapCompletedAt: '2026-01-01T00:00:00Z',
        lastSyncedModifiedId: '2026-01-01T00:00:00Z',
        csvEtag: 'future-etag',
        csvLastModified: 'future-last-modified',
        extractionSchemaVersion: osvClient.EXTRACTION_SCHEMA_VERSION + 1,
      });

      const exitCalls = [];
      const store = makeStore({baseUrl: 'http://unused'}, client, {
        exitProcess: code => exitCalls.push(code),
      });
      await store.ready;

      assert.deepEqual(
        exitCalls,
        [1],
        'a newer-than-this-code stored version must call exitProcess(1) exactly once',
      );
      assert.equal(
        store._bootstrapCompletedAt,
        null,
        'must not have applied the newer stored state as if it were current',
      );
    },
  );

  await check(
    'runSyncCycle() sits out a cycle (does not bootstrap or incrementally sync) if the shared state has moved to a newer schema mid-operation',
    async () => {
      const client = makeFakeDynamoClient();
      const osv = await startMockOsvServer();
      try {
        await osv.setFixtureRecords([]);
        osv.setCsvRows([]);
        const store = makeStore({baseUrl: osv.baseUrl}, client);
        await bootstrapStore(store); // establishes this pod at the current schema version

        // Simulate some other, already-upgraded instance moving the shared
        // state forward in the meantime.
        client.table.set('__sync_state__', {
          ...client.table.get('__sync_state__'),
          extractionSchemaVersion: osvClient.EXTRACTION_SCHEMA_VERSION + 1,
        });

        const callCountBefore = client.callCount();
        await store.runSyncCycle();
        // Only the one extra getItem(SYNC_STATE_KEY) read -- no bootstrap
        // (a Scan) and no incremental sync (a modified_id.csv fetch, which
        // would show up as an HTTP call, not a DynamoDB one, but the point
        // is neither branch below the version check should have run at all).
        assert.equal(
          client.callCount(),
          callCountBefore + 1,
          'should only perform the one version-check read, then return -- no bootstrap or incremental sync work',
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

  // --- per-advisory MAL entries, bootstrap watermark and write retries ---

  await check(
    'two MAL advisories for one package each keep their own range; an update or withdrawal of one leaves the other',
    async () => {
      const osv = await startMockOsvServer();
      const client = makeFakeDynamoClient();
      try {
        await osv.setFixtureRecords([
          makeOsvRecord({
            id: 'MAL-A',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'twice',
            introduced: '1.0.0',
            fixed: '2.0.0',
          }),
          makeOsvRecord({
            id: 'MAL-B',
            modified: '2025-01-02T00:00:00Z',
            packageName: 'twice',
            introduced: '3.0.0',
            fixed: '4.0.0',
          }),
        ]);
        osv.setCsvRows([]);
        const store = makeStore({baseUrl: osv.baseUrl}, client);
        await bootstrapStore(store);

        assert.deepEqual(store.check('twice', '1.5.0')?.malIds, ['MAL-A']);
        assert.deepEqual(store.check('twice', '3.5.0')?.malIds, ['MAL-B']);
        assert.equal(client.table.get('twice').mals.length, 2);

        // MAL-A narrows its range; MAL-B must still hold.
        osv.setCsvEtag('etag-v2');
        osv.setCsvRows([{modified: '2030-01-01T00:00:00Z', id: 'MAL-A'}]);
        osv.setRecord(
          'MAL-A',
          makeOsvRecord({
            id: 'MAL-A',
            modified: '2030-01-01T00:00:00Z',
            packageName: 'twice',
            introduced: '1.0.0',
            fixed: '1.2.0',
          }),
        );
        await store.runSyncCycle();
        assert.equal(store.check('twice', '1.5.0'), null);
        assert.deepEqual(store.check('twice', '1.1.0')?.malIds, ['MAL-A']);
        assert.deepEqual(store.check('twice', '3.5.0')?.malIds, ['MAL-B']);

        // Withdrawing MAL-B leaves MAL-A.
        osv.setCsvEtag('etag-v3');
        osv.setCsvRows([{modified: '2030-02-01T00:00:00Z', id: 'MAL-B'}]);
        osv.setRecord(
          'MAL-B',
          makeOsvRecord({
            id: 'MAL-B',
            modified: '2030-02-01T00:00:00Z',
            packageName: 'twice',
            withdrawn: true,
          }),
        );
        await store.runSyncCycle();
        assert.equal(store.check('twice', '3.5.0'), null);
        assert.deepEqual(store.check('twice', '1.1.0')?.malIds, ['MAL-A']);
        assert.deepEqual(
          client.table.get('twice').mals.map(mal => mal.id),
          ['MAL-A'],
        );
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    "bootstrap's watermark is the zip's newest record, so a CSV row newer than the zip is fetched by the next cycle",
    async () => {
      const osv = await startMockOsvServer();
      const client = makeFakeDynamoClient();
      try {
        await osv.setFixtureRecords([
          makeOsvRecord({
            id: 'MAL-OLD',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'old-pkg',
          }),
        ]);
        // The CSV is a newer snapshot than the zip: it already lists a
        // record the zip doesn't carry.
        osv.setCsvRows([
          {modified: '2026-01-01T00:00:00Z', id: 'MAL-GAP'},
          {modified: '2025-01-01T00:00:00Z', id: 'MAL-OLD'},
        ]);
        osv.setRecord(
          'MAL-GAP',
          makeOsvRecord({
            id: 'MAL-GAP',
            modified: '2026-01-01T00:00:00Z',
            packageName: 'gap-pkg',
          }),
        );
        const store = makeStore({baseUrl: osv.baseUrl}, client);
        await bootstrapStore(store);
        assert.equal(store._lastSyncedModifiedId, '2025-01-01T00:00:00Z');
        assert.equal(store.check('gap-pkg', '1.0.0'), null);

        await store.runSyncCycle();
        assert.ok(store.check('gap-pkg', '1.0.0'), 'the gap record is applied');
        assert.equal(store._lastSyncedModifiedId, '2026-01-01T00:00:00Z');
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'bootstrap is not complete while the store refused items: they are enforced in memory and retried alone next cycle',
    async () => {
      const osv = await startMockOsvServer();
      const inner = makeFakeDynamoClient();
      let refuseBatches = true;
      const client = {
        table: inner.table,
        async send(command) {
          if (refuseBatches && command instanceof BatchWriteCommand) {
            throw new Error('simulated BatchWriteCommand failure');
          }
          return inner.send(command);
        },
      };
      try {
        await osv.setFixtureRecords([
          makeOsvRecord({
            id: 'MAL-2025-50',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'refused-pkg',
          }),
        ]);
        osv.setCsvRows([]);
        const store = makeStore({baseUrl: osv.baseUrl}, client);
        await store.ready;
        assert.equal(await store.runSyncCycle(), false);
        assert.equal(store._bootstrapCompletedAt, null);
        assert.ok(store.check('refused-pkg', '1.0.0'), 'enforced in memory');
        assert.equal(client.table.has('refused-pkg'), false);
        assert.equal(client.table.has('__sync_state__'), false);

        refuseBatches = false;
        const requestsBefore = osv.requestCount();
        assert.equal(await store.runSyncCycle(), true);
        assert.equal(osv.requestCount(), requestsBefore, 'no second download');
        assert.ok(client.table.has('refused-pkg'));
        assert.ok(client.table.get('__sync_state__').bootstrapCompletedAt);
      } finally {
        osv.server.close();
      }
    },
  );

  // --- failure handling: backoff, staleness alarm, warm-start retry ---

  function makeFlakyClient() {
    const inner = makeFakeDynamoClient();
    const client = {
      table: inner.table,
      down: true,
      async send(command) {
        if (client.down) throw new Error('store unreachable');
        return inner.send(command);
      },
    };
    return client;
  }

  await check(
    'a store that cannot be reached is retried on a backoff, not in a tight loop',
    async () => {
      const osv = await startMockOsvServer();
      try {
        await osv.setFixtureRecords([]);
        osv.setCsvRows([]);
        const store = makeStore(
          {baseUrl: osv.baseUrl, pollJitter: 0},
          makeFlakyClient(),
        );
        await store.ready; // the warm start fails: failure 1
        assert.equal(store._nextDelayMs(), 30000);
        await store._tick();
        assert.equal(store._nextDelayMs(), 60000);
        await store._tick();
        assert.equal(store._nextDelayMs(), 120000);
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'after staleAfterCycles failed cycles the sync raises one alarm (log and webhook), and reports recovery',
    async () => {
      const osv = await startMockOsvServer();
      const receiver = await startWebhookReceiver();
      try {
        await osv.setFixtureRecords([]);
        osv.setCsvRows([]);
        const client = makeFlakyClient();
        const logger = makeCapturingLogger();
        const store = makeStore(
          {baseUrl: osv.baseUrl, staleAfterCycles: 3},
          client,
          {
            logger,
            webhookConfig: {
              url: `${receiver.url}/alert`,
              body: '{"event":"{{event}}","failures":"{{failures}}"}',
            },
          },
        );
        await store.ready; // 1
        await store._tick(); // 2
        await store._tick(); // 3 -- the alarm
        await store._tick(); // 4 -- no second alarm
        await waitFor(() => receiver.requests.length >= 1);
        await new Promise(resolve => setTimeout(resolve, 100));
        assert.equal(receiver.requests.length, 1);
        assert.deepEqual(JSON.parse(receiver.requests[0].body), {
          event: 'osv_sync_stale',
          failures: '3',
        });
        assert.ok(
          logger.calls.error.some(([, message]) => /going stale/.test(message)),
        );

        client.down = false;
        await store._tick();
        await waitFor(() => receiver.requests.length >= 2);
        assert.equal(
          JSON.parse(receiver.requests[1].body).event,
          'osv_sync_recovered',
        );
        assert.equal(store._consecutiveFailures, 0);
      } finally {
        osv.server.close();
        await receiver.close();
      }
    },
  );

  await check(
    'a warm start that failed at startup is retried by the next cycle, before any re-bootstrap',
    async () => {
      const osv = await startMockOsvServer();
      try {
        await osv.setFixtureRecords([]);
        osv.setCsvRows([]);
        const client = makeFlakyClient();
        client.table.set('__sync_state__', {
          pk: '__sync_state__',
          extractionSchemaVersion: osvClient.EXTRACTION_SCHEMA_VERSION,
          bootstrapCompletedAt: '2025-01-01T00:00:00Z',
          lastSyncedModifiedId: '2025-01-01T00:00:00Z',
          csvEtag: 'etag-v1',
        });
        client.table.set('stored-pkg', {
          pk: 'stored-pkg',
          mals: [
            {id: 'MAL-1', vulnerableVersions: '*', originCount: 1, sources: []},
          ],
        });
        const store = makeStore({baseUrl: osv.baseUrl}, client);
        await store.ready; // fails: store down
        assert.equal(store.check('stored-pkg', '1.0.0'), null);

        client.down = false;
        assert.equal(await store.runSyncCycle(), true);
        assert.ok(
          store.check('stored-pkg', '1.0.0'),
          'loaded by the retried warm start',
        );
        assert.ok(store._bootstrapCompletedAt, 'no re-bootstrap needed');
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'an OSV download that stalls fails within the stall timeout, and one past its byte limit fails too',
    async () => {
      const server = http.createServer((req, res) => {
        if (req.url.endsWith('modified_id.csv')) {
          res.writeHead(200, {'content-type': 'text/csv'});
          res.write('2030-01-01T00:00:00Z,MAL-1\n'); // then nothing more, ever
          return;
        }
        if (req.url.endsWith('all.zip') && req.headers['x-chunked']) {
          res.writeHead(200);
          res.end(Buffer.alloc(5000));
          return;
        }
        res.writeHead(200, {'content-length': '5000'});
        res.end(Buffer.alloc(5000));
      });
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      const baseUrl = `http://127.0.0.1:${server.address().port}/npm/`;
      // A fetch that never settles fails here after 3s, instead of hanging
      // the run.
      const within3s = promise =>
        Promise.race([
          promise,
          new Promise((resolve, reject) =>
            setTimeout(
              () => reject(new Error('still waiting after 3s')),
              3000,
            ).unref(),
          ),
        ]);
      try {
        await assert.rejects(
          within3s(osvClient.fetchModifiedCsv({baseUrl, timeoutMs: 200})),
          /stalled for 200ms/,
        );

        const drain = async iterator => {
          for await (const record of iterator) void record;
        };
        await assert.rejects(
          within3s(
            drain(
              osvClient.fetchAllRecords({
                baseUrl,
                timeoutMs: 1000,
                maxBytes: 1000,
              }),
            ),
          ),
          /over the 1000-byte limit/,
        );
      } finally {
        server.closeAllConnections();
        server.close();
      }
    },
  );

  await check(
    'the retroactive alert reads raw local storage, not the filtered view that has already hidden the version',
    async () => {
      const osv = await startMockOsvServer();
      const client = makeFakeDynamoClient();
      try {
        await osv.setFixtureRecords([]);
        osv.setCsvRows([]);
        const logger = makeCapturingLogger();
        const store = makeStore({baseUrl: osv.baseUrl}, client, {logger});
        await bootstrapStore(store);

        const registryStorage = makeFakeRegistryStorage();
        registryStorage.setExisting('hidden-pkg', {
          '1.0.0': {version: '1.0.0'},
        });
        registryStorage.filteredView('hidden-pkg', {}); // filter_metadata already removed it
        store.attachRegistryStorage(registryStorage);

        osv.setCsvEtag('etag-v2');
        osv.setCsvRows([{modified: '2030-01-01T00:00:00Z', id: 'MAL-2030-9'}]);
        osv.setRecord(
          'MAL-2030-9',
          makeOsvRecord({
            id: 'MAL-2030-9',
            modified: '2030-01-01T00:00:00Z',
            packageName: 'hidden-pkg',
          }),
        );
        await store.runSyncCycle();
        assert.equal(logger.calls.fatal.length, 1);
        assert.equal(logger.calls.fatal[0][0].ver, '1.0.0');
      } finally {
        osv.server.close();
      }
    },
  );

  await check(
    'getCveAdvisories() charges a shared budget and throws ADVISORY_BUDGET once it is spent',
    async () => {
      const osv = await startMockOsvServer();
      try {
        await osv.setFixtureRecords([
          makeGhsaRecord({
            id: 'GHSA-aaaa-aaaa-aaaa',
            modified: '2025-01-01T00:00:00Z',
            packageName: 'cve-pkg',
            fixed: '2.0.0',
          }),
        ]);
        osv.setCsvRows([]);
        const store = makeStore({baseUrl: osv.baseUrl}, makeFakeDynamoClient());
        await bootstrapStore(store);
        const budget = {remaining: 3};
        assert.equal(
          store.getCveAdvisories('cve-pkg', ['1.0.0', '1.1.0'], budget).length,
          1,
        );
        assert.equal(budget.remaining, 1);
        assert.throws(
          () => store.getCveAdvisories('cve-pkg', ['1.0.0', '1.1.0'], budget),
          err => err.code === 'ADVISORY_BUDGET',
        );
        // A package with no advisories costs nothing.
        assert.deepEqual(
          store.getCveAdvisories('clean-pkg', ['1.0.0'], {remaining: 0}),
          [],
        );
      } finally {
        osv.server.close();
      }
    },
  );

  console.log(`\n${passed} check(s) passed.`);
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
