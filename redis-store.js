'use strict';

// Redis backend for the OSV malicious-package/CVE blocklist. `ioredis` is
// an optional peer dependency (see package.json) -- this module must only
// ever be reached via a runtime-conditional require() from
// malicious-packages.js's _createStore(), never a static top-level import
// elsewhere, or every filesystem/DynamoDB-only install would need ioredis
// on disk too.
//
// No connection pool: unlike some Redis use cases, nothing here does a
// blocking read, so a single client is sufficient.

const Redis = require('ioredis');

const SCAN_COUNT = 500; // per-iteration hint to SCAN, not a hard limit
const PIPELINE_CHUNK_SIZE = 500;

function createRedisStore(config, options) {
  const url = config.url;
  if (!url) {
    throw new Error('security-filter: osv.redis requires url to be set');
  }
  const keyPrefix = config.keyPrefix ?? '';
  // Test-only override -- production always connects a real ioredis client.
  const redis = options.redisClient ?? new Redis(url);

  function keyFor(pk) {
    return `${keyPrefix}${pk}`;
  }

  // SCAN, not KEYS -- KEYS blocks the server for the duration of the scan
  // over the whole keyspace, which at ~215k entries is exactly the kind of
  // thing this plugin's design elsewhere (DynamoDB's sequential-not-parallel
  // Scan, OSV's conditional-GET polling) goes out of its way to avoid.
  async function scanAll() {
    const items = [];
    let cursor = '0';
    do {
      const [nextCursor, keys] = await redis.scan(
        cursor,
        'MATCH',
        `${keyPrefix}*`,
        'COUNT',
        SCAN_COUNT,
      );
      cursor = nextCursor;
      if (keys.length > 0) {
        const values = await redis.mget(...keys);
        for (const value of values) {
          if (value) items.push(JSON.parse(value));
        }
      }
    } while (cursor !== '0');
    return items;
  }

  async function getItem(pk) {
    const value = await redis.get(keyFor(pk));
    return value ? JSON.parse(value) : undefined;
  }

  async function putItem(item) {
    await redis.set(keyFor(item.pk), JSON.stringify(item));
  }

  async function deleteItem(pk) {
    await redis.del(keyFor(pk));
  }

  // No real partial-failure model in a Redis pipeline the way DynamoDB's
  // BatchWriteItem has -- a pipeline call that itself errors (as opposed to
  // a per-command reply) fails every item in that chunk, matching this
  // plugin's existing all-or-nothing-per-cycle philosophy elsewhere (e.g.
  // incremental sync's watermark advancement).
  async function putItems(items) {
    const failed = [];
    for (let i = 0; i < items.length; i += PIPELINE_CHUNK_SIZE) {
      const chunk = items.slice(i, i + PIPELINE_CHUNK_SIZE);
      try {
        const pipeline = redis.pipeline();
        for (const item of chunk)
          pipeline.set(keyFor(item.pk), JSON.stringify(item));
        const results = await pipeline.exec();
        results.forEach(([err], idx) => {
          if (err) failed.push(chunk[idx]);
        });
      } catch {
        failed.push(...chunk);
      }
    }
    return failed;
  }

  async function close() {
    await redis.quit();
  }

  return {scanAll, getItem, putItem, putItems, deleteItem, close};
}

module.exports = {createRedisStore};
