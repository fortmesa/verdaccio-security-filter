'use strict';

// Filesystem backend for the OSV malicious-package/CVE blocklist -- zero
// optional dependencies (uses only node:fs), so unlike redis-store.js and
// dynamodb-store.js this module is always safe to require() unconditionally.
// Intended for small/dev deployments that don't want to provision Redis or
// DynamoDB just to try the OSV blocklist feature.
//
// One JSON file per item, named after a URL-safe encoding of its `pk` --
// encodeURIComponent() escapes every '/', so path.join(dir, encoded) can
// never escape `dir` even for an adversarial pk like '../../etc/passwd'
// (it becomes the literal filename '..%2F..%2Fetc%2Fpasswd.json').
// No TTL/expiry concept -- this data persists indefinitely, same as the
// DynamoDB table.

const fs = require('node:fs/promises');
const path = require('node:path');

const WRITE_CONCURRENCY = 50;

function createFilesystemStore(config) {
  const dir = config.path;
  if (!dir) {
    throw new Error('security-filter: osv.filesystem requires path to be set');
  }

  let dirReady = null;
  function ensureDir() {
    dirReady ??= fs.mkdir(dir, {recursive: true});
    return dirReady;
  }

  function fileFor(pk) {
    return path.join(dir, `${encodeURIComponent(pk)}.json`);
  }

  async function scanAll() {
    await ensureDir();
    const names = await fs.readdir(dir);
    const items = [];
    for (const name of names) {
      if (!name.endsWith('.json')) continue;
      try {
        items.push(JSON.parse(await fs.readFile(path.join(dir, name), 'utf8')));
      } catch {
        // A partially-written or corrupt file from a crashed prior write --
        // skip it rather than fail the whole scan; the next sync cycle
        // overwrites it with fresh data anyway.
      }
    }
    return items;
  }

  async function getItem(pk) {
    try {
      return JSON.parse(await fs.readFile(fileFor(pk), 'utf8'));
    } catch (err) {
      if (err.code === 'ENOENT') return undefined;
      throw err;
    }
  }

  async function putItem(item) {
    await ensureDir();
    await fs.writeFile(fileFor(item.pk), JSON.stringify(item));
  }

  async function deleteItem(pk) {
    try {
      await fs.unlink(fileFor(pk));
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
  }

  // No real "batch" primitive on a filesystem -- write each item
  // independently, capped at WRITE_CONCURRENCY in flight at once, and
  // report whichever ones failed (same contract as the other backends).
  async function putItems(items) {
    await ensureDir();
    const failed = [];
    for (let i = 0; i < items.length; i += WRITE_CONCURRENCY) {
      const wave = items.slice(i, i + WRITE_CONCURRENCY);
      await Promise.all(
        wave.map(async item => {
          try {
            await putItem(item);
          } catch {
            failed.push(item);
          }
        }),
      );
    }
    return failed;
  }

  async function close() {
    // No open handle to release.
  }

  return {scanAll, getItem, putItem, putItems, deleteItem, close};
}

module.exports = {createFilesystemStore};
