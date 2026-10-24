'use strict';

// Manual smoke test for the two non-DynamoDB OSV storage backends
// (filesystem-store.js, redis-store.js) -- no framework, matching the house
// style. Run with:
//   node verdaccio-security-filter/test/smoke-storage-backends.js
// The DynamoDB backend keeps its existing, deeper coverage in
// test/smoke-malicious-packages.js (it's the reference/default backend and
// must not regress); this file covers the CRUD contract
// {scanAll, getItem, putItem, putItems, deleteItem, close} that all three
// backends share, for the two newer ones specifically.

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {createFilesystemStore} = require('../filesystem-store.js');
const {createRedisStore} = require('../redis-store.js');

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

  // --- filesystem-store.js ---

  async function withTempDir(fn) {
    const dir = await fs.mkdtemp(
      path.join(os.tmpdir(), 'security-filter-storage-test-'),
    );
    try {
      await fn(dir);
    } finally {
      await fs.rm(dir, {recursive: true, force: true});
    }
  }

  await check('createFilesystemStore throws if path is not set', () => {
    assert.throws(() => createFilesystemStore({}), /path/);
  });

  await check(
    'filesystem: putItem/getItem round-trips, missing key returns undefined',
    async () => {
      await withTempDir(async dir => {
        const store = createFilesystemStore({path: dir});
        await store.putItem({
          pk: 'left-pad',
          ranges: [{introduced: '0', fixed: null}],
        });
        const item = await store.getItem('left-pad');
        assert.deepEqual(item, {
          pk: 'left-pad',
          ranges: [{introduced: '0', fixed: null}],
        });
        assert.equal(await store.getItem('never-written'), undefined);
      });
    },
  );

  await check(
    'filesystem: scanAll returns every item written, including via putItems',
    async () => {
      await withTempDir(async dir => {
        const store = createFilesystemStore({path: dir});
        await store.putItem({pk: 'pkg-a', ranges: []});
        const unwritten = await store.putItems([
          {pk: 'pkg-b', ranges: []},
          {pk: 'pkg-c', ranges: []},
        ]);
        assert.deepEqual(unwritten, []);
        const items = await store.scanAll();
        assert.deepEqual(items.map(i => i.pk).sort(), [
          'pkg-a',
          'pkg-b',
          'pkg-c',
        ]);
      });
    },
  );

  await check(
    'filesystem: deleteItem removes the item; deleting an already-missing key does not throw',
    async () => {
      await withTempDir(async dir => {
        const store = createFilesystemStore({path: dir});
        await store.putItem({pk: 'gone-soon', ranges: []});
        await store.deleteItem('gone-soon');
        assert.equal(await store.getItem('gone-soon'), undefined);
        await store.deleteItem('gone-soon'); // must not throw on a second delete
      });
    },
  );

  await check(
    'filesystem: a path-traversal-shaped pk cannot escape the storage directory',
    async () => {
      await withTempDir(async dir => {
        const store = createFilesystemStore({path: dir});
        const evilPk = '../../etc/passwd';
        await store.putItem({pk: evilPk, ranges: []});

        // The file must land INSIDE dir as one flat, encoded filename -- if
        // encodeURIComponent() failed to neutralize the '../' segments, this
        // write would instead have created (or reached into) a real
        // subdirectory structure, and dir itself would show zero or multiple
        // entries instead of exactly one flat file.
        const filesInDir = await fs.readdir(dir, {withFileTypes: true});
        assert.equal(filesInDir.length, 1);
        assert.ok(
          filesInDir[0].isFile(),
          'must be a plain file directly inside dir, not a subdirectory',
        );
        assert.ok(
          !filesInDir[0].name.includes('/'),
          'the on-disk filename must not contain a path separator',
        );
        assert.equal(filesInDir[0].name, `${encodeURIComponent(evilPk)}.json`);

        const roundTripped = await store.getItem(evilPk);
        assert.deepEqual(roundTripped, {pk: evilPk, ranges: []});
      });
    },
  );

  await check(
    'filesystem: putItems reports the subset that failed to write',
    async () => {
      await withTempDir(async dir => {
        const store = createFilesystemStore({path: dir});
        const circular = {pk: 'bad-item'};
        circular.self = circular; // JSON.stringify throws on this -- forces a real, unmocked failure
        const unwritten = await store.putItems([
          {pk: 'good-item', ranges: []},
          circular,
        ]);
        assert.deepEqual(unwritten, [circular]);
        assert.ok(await store.getItem('good-item'));
        assert.equal(await store.getItem('bad-item'), undefined);
      });
    },
  );

  // --- redis-store.js ---

  // Fakes exactly the ioredis surface redis-store.js uses
  // (get/set/del/mget/scan/pipeline/quit), backed by a plain Map, with
  // failure-injection hooks -- same "fake exactly the interface under test
  // uses" approach as test/smoke-malicious-packages.js's fake DynamoDB
  // client, since ioredis is an optional peer dependency and this repo has
  // no precedent for spinning up a real Redis server in tests either.
  function makeFakeRedisClient() {
    const table = new Map();
    const flags = {failNextPipelineExec: false};
    let quitCalled = false;

    return {
      table,
      quitCalled: () => quitCalled,
      failNextPipelineExec() {
        flags.failNextPipelineExec = true;
      },
      async get(key) {
        return table.has(key) ? table.get(key) : null;
      },
      async set(key, value) {
        table.set(key, value);
        return 'OK';
      },
      async del(key) {
        table.delete(key);
        return 1;
      },
      async mget(...keys) {
        return keys.map(k => (table.has(k) ? table.get(k) : null));
      },
      // Paginates 2 keys per call regardless of the requested COUNT hint --
      // exercises redis-store.js's do/while cursor loop the same way a real
      // multi-page SCAN would, without needing a real server.
      async scan(cursor, ...args) {
        const matchIdx = args.indexOf('MATCH');
        const pattern = matchIdx !== -1 ? args[matchIdx + 1] : '*';
        const prefix = pattern.endsWith('*') ? pattern.slice(0, -1) : pattern;
        const allKeys = Array.from(table.keys()).filter(k =>
          k.startsWith(prefix),
        );
        const pageSize = 2;
        const start = Number(cursor);
        const page = allKeys.slice(start, start + pageSize);
        const nextCursor =
          start + pageSize >= allKeys.length ? '0' : String(start + pageSize);
        return [nextCursor, page];
      },
      pipeline() {
        const commands = [];
        const self = {
          set(key, value) {
            commands.push({key, value});
            return self;
          },
          async exec() {
            if (flags.failNextPipelineExec) {
              flags.failNextPipelineExec = false;
              throw new Error('simulated pipeline exec failure');
            }
            return commands.map(cmd => {
              table.set(cmd.key, cmd.value);
              return [null, 'OK'];
            });
          },
        };
        return self;
      },
      async quit() {
        quitCalled = true;
        return 'OK';
      },
    };
  }

  await check('createRedisStore throws if url is not set', () => {
    assert.throws(
      () => createRedisStore({}, {redisClient: makeFakeRedisClient()}),
      /url/,
    );
  });

  await check(
    'redis: putItem/getItem round-trips, missing key returns undefined',
    async () => {
      const client = makeFakeRedisClient();
      const store = createRedisStore(
        {url: 'redis://localhost:6379'},
        {redisClient: client},
      );
      await store.putItem({pk: 'left-pad', ranges: []});
      assert.deepEqual(await store.getItem('left-pad'), {
        pk: 'left-pad',
        ranges: [],
      });
      assert.equal(await store.getItem('never-written'), undefined);
    },
  );

  await check('redis: keys are namespaced by keyPrefix', async () => {
    const client = makeFakeRedisClient();
    const store = createRedisStore(
      {url: 'redis://localhost:6379', keyPrefix: 'osv:'},
      {redisClient: client},
    );
    await store.putItem({pk: 'left-pad', ranges: []});
    assert.ok(client.table.has('osv:left-pad'));
    assert.ok(!client.table.has('left-pad'));
  });

  await check(
    'redis: scanAll paginates across multiple SCAN calls and returns every item',
    async () => {
      const client = makeFakeRedisClient();
      const store = createRedisStore(
        {url: 'redis://localhost:6379'},
        {redisClient: client},
      );
      const items = Array.from({length: 5}, (_, i) => ({
        pk: `pkg-${i}`,
        ranges: [],
      }));
      await store.putItems(items);
      const scanned = await store.scanAll();
      assert.deepEqual(
        scanned.map(i => i.pk).sort(),
        items.map(i => i.pk).sort(),
      );
    },
  );

  await check(
    'redis: putItems batches via pipeline and reports zero failures on success',
    async () => {
      const client = makeFakeRedisClient();
      const store = createRedisStore(
        {url: 'redis://localhost:6379'},
        {redisClient: client},
      );
      const unwritten = await store.putItems([
        {pk: 'a', ranges: []},
        {pk: 'b', ranges: []},
      ]);
      assert.deepEqual(unwritten, []);
      assert.ok(client.table.has('a'));
      assert.ok(client.table.has('b'));
    },
  );

  await check(
    'redis: a pipeline exec failure fails every item in that chunk',
    async () => {
      const client = makeFakeRedisClient();
      client.failNextPipelineExec();
      const store = createRedisStore(
        {url: 'redis://localhost:6379'},
        {redisClient: client},
      );
      const items = [
        {pk: 'a', ranges: []},
        {pk: 'b', ranges: []},
      ];
      const unwritten = await store.putItems(items);
      assert.deepEqual(unwritten, items);
      assert.ok(
        !client.table.has('a'),
        'nothing from a failed pipeline should have been written',
      );
    },
  );

  await check('redis: deleteItem removes the item', async () => {
    const client = makeFakeRedisClient();
    const store = createRedisStore(
      {url: 'redis://localhost:6379'},
      {redisClient: client},
    );
    await store.putItem({pk: 'gone-soon', ranges: []});
    await store.deleteItem('gone-soon');
    assert.equal(await store.getItem('gone-soon'), undefined);
  });

  await check('redis: close() quits the underlying client', async () => {
    const client = makeFakeRedisClient();
    const store = createRedisStore(
      {url: 'redis://localhost:6379'},
      {redisClient: client},
    );
    await store.close();
    assert.equal(client.quitCalled(), true);
  });

  // A minimal RESP2 server -- just the commands redis-store.js sends, plus
  // whatever ioredis asks on connect -- so the store runs through the real
  // ioredis client, not a stand-in for it.
  async function startRespServer() {
    const net = require('node:net');
    const data = new Map();
    const bulk = value =>
      value === null || value === undefined
        ? '$-1\r\n'
        : `$${Buffer.byteLength(value)}\r\n${value}\r\n`;
    const array = items => `*${items.length}\r\n${items.join('')}`;
    function handle(args) {
      const [command, ...rest] = args;
      switch (command.toUpperCase()) {
        case 'GET':
          return bulk(data.get(rest[0]) ?? null);
        case 'SET':
          data.set(rest[0], rest[1]);
          return '+OK\r\n';
        case 'DEL':
          return `:${rest.filter(k => data.delete(k)).length}\r\n`;
        case 'MGET':
          return array(rest.map(k => bulk(data.get(k) ?? null)));
        case 'SCAN': {
          const match =
            rest[rest.findIndex(a => a.toUpperCase() === 'MATCH') + 1] ?? '*';
          const prefix = match.endsWith('*') ? match.slice(0, -1) : match;
          const keys = [...data.keys()].filter(k => k.startsWith(prefix));
          return array([bulk('0'), array(keys.map(bulk))]);
        }
        case 'INFO':
          return bulk('# Server\r\nredis_version:7.2.0\r\nloading:0\r\n');
        case 'QUIT':
          return '+OK\r\n';
        default:
          return '+OK\r\n';
      }
    }
    const server = net.createServer(socket => {
      let buffer = Buffer.alloc(0);
      socket.on('data', chunk => {
        buffer = Buffer.concat([buffer, chunk]);
        for (;;) {
          const text = buffer.toString('latin1');
          if (!text.startsWith('*')) return;
          let pos = text.indexOf('\r\n');
          if (pos === -1) return;
          const count = Number(text.slice(1, pos));
          let cursor = pos + 2;
          const args = [];
          for (let i = 0; i < count; i++) {
            const end = text.indexOf('\r\n', cursor);
            if (end === -1) return;
            const len = Number(text.slice(cursor + 1, end));
            if (text.length < end + 2 + len + 2) return;
            args.push(buffer.subarray(end + 2, end + 2 + len).toString('utf8'));
            cursor = end + 2 + len + 2;
          }
          buffer = buffer.subarray(cursor);
          socket.write(handle(args));
          if (args[0].toUpperCase() === 'QUIT') socket.end();
        }
      });
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    return {server, data, url: `redis://127.0.0.1:${server.address().port}`};
  }

  await check(
    'redis: the store round-trips through the real ioredis client',
    async () => {
      const resp = await startRespServer();
      const store = createRedisStore({url: resp.url, keyPrefix: 'osv:'}, {});
      try {
        const failed = await store.putItems([
          {pk: 'left-pad', mals: [{id: 'MAL-1', vulnerableVersions: '*'}]},
          {pk: 'right-pad', cves: []},
        ]);
        assert.deepEqual(failed, []);
        await store.putItem({pk: '__sync_state__', bootstrapCompletedAt: 'x'});
        resp.data.set('unrelated', 'not json at all');
        resp.data.set('osv:not-ours', '{"pk":"someone-else"}');
        assert.deepEqual((await store.getItem('left-pad')).mals[0].id, 'MAL-1');
        const all = await store.scanAll();
        assert.deepEqual(all.map(item => item.pk).sort(), [
          '__sync_state__',
          'left-pad',
          'right-pad',
        ]);
        await store.deleteItem('right-pad');
        assert.equal(await store.getItem('right-pad'), undefined);
      } finally {
        await store.close();
        resp.server.close();
      }
    },
  );

  await check(
    "redis: a shared database's foreign keys are skipped by scanAll, not fatal to it",
    async () => {
      const client = makeFakeRedisClient();
      const store = createRedisStore(
        {url: 'redis://unused'},
        {redisClient: client},
      );
      await store.putItem({pk: 'left-pad', cves: []});
      client.table.set('session:abc', 'opaque');
      client.table.set('config', '{"theme":"dark"}');
      client.table.set('other-app', '{"pk":"spoofed"}');
      const all = await store.scanAll();
      assert.deepEqual(
        all.map(item => item.pk),
        ['left-pad'],
      );
    },
  );

  console.log(`\n${passed} check(s) passed.`);
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
