'use strict';

// DynamoDB backend for the OSV malicious-package/CVE blocklist -- the
// reference/default backend (see docs/plugins/security-filter.md's "Storage
// backends" section). Extracted from malicious-packages.js verbatim; no
// behavior change from what this repo has run since the OSV feature shipped.
//
// @aws-sdk/client-dynamodb and @aws-sdk/lib-dynamodb are optional peer
// dependencies (see package.json) -- this module must only ever be reached
// via a runtime-conditional require() from malicious-packages.js's
// _createStore(), never a static top-level import elsewhere, or every
// filesystem/Redis-only install would need the AWS SDK on disk too.

const {DynamoDBClient} = require('@aws-sdk/client-dynamodb');
const {
  DynamoDBDocumentClient,
  ScanCommand,
  GetCommand,
  PutCommand,
  DeleteCommand,
  BatchWriteCommand,
} = require('@aws-sdk/lib-dynamodb');

const BATCH_SIZE = 25; // DynamoDB BatchWriteItem's own per-request limit
const BATCH_CONCURRENCY = 10;
const MAX_WRITE_RETRIES = 5;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function jitteredBackoff(attempt) {
  const base = Math.min(30000, 500 * 2 ** attempt);
  return base / 2 + Math.random() * (base / 2);
}

function createDynamoDbStore(config, options) {
  const tableName = config.tableName ?? 'verdaccio-malicious-packages';
  const region = config.region ?? 'us-east-1';
  // Namespaces every pk this plugin writes, so the table can be shared with
  // unrelated items -- same purpose as redis-store.js's keyPrefix, applied
  // to the partition key attribute itself since Dynamo (unlike Redis) has
  // no separate outer-key/value distinction to hang a prefix on.
  const keyPrefix = config.keyPrefix ?? '';
  const docClient =
    options.docClient ??
    DynamoDBDocumentClient.from(new DynamoDBClient({region}));
  // Test-only override -- production always uses MAX_WRITE_RETRIES; tests
  // that intentionally inject a persistent write failure set this low so
  // the retry backoff doesn't make the test slow.
  const maxWriteRetries = options.maxWriteRetries ?? MAX_WRITE_RETRIES;
  const logger = options.logger;

  function keyFor(pk) {
    return `${keyPrefix}${pk}`;
  }
  function stripPrefix(item) {
    return item ? {...item, pk: item.pk.slice(keyPrefix.length)} : item;
  }

  // Paginated Scan over the whole table. Deliberately sequential, not
  // Segment/TotalSegments parallel -- see docs/plugins/security-filter.md's
  // "Cost characteristics" section for why that's not worth the complexity
  // at the current ~215k-entry data volume (a few seconds either way).
  // Filters server-side on keyPrefix (when set) so a shared table's
  // unrelated items are never even returned, let alone loaded into memory.
  async function scanAll() {
    const items = [];
    let ExclusiveStartKey;
    do {
      const result = await docClient.send(
        new ScanCommand({
          TableName: tableName,
          ExclusiveStartKey,
          ...(keyPrefix
            ? {
                FilterExpression: 'begins_with(pk, :prefix)',
                ExpressionAttributeValues: {':prefix': keyPrefix},
              }
            : {}),
        }),
      );
      items.push(...(result.Items ?? []));
      ExclusiveStartKey = result.LastEvaluatedKey;
    } while (ExclusiveStartKey);
    return items.map(stripPrefix);
  }

  async function getItem(pk) {
    const result = await docClient.send(
      new GetCommand({TableName: tableName, Key: {pk: keyFor(pk)}}),
    );
    return stripPrefix(result.Item);
  }

  async function putItem(item) {
    await docClient.send(
      new PutCommand({
        TableName: tableName,
        Item: {...item, pk: keyFor(item.pk)},
      }),
    );
  }

  async function deleteItem(pk) {
    await docClient.send(
      new DeleteCommand({TableName: tableName, Key: {pk: keyFor(pk)}}),
    );
  }

  async function writeChunkWithRetry(chunk, attempt = 0) {
    if (chunk.length === 0) return [];
    try {
      const result = await docClient.send(
        new BatchWriteCommand({
          RequestItems: {
            [tableName]: chunk.map(item => ({PutRequest: {Item: item}})),
          },
        }),
      );
      const unprocessed = (result.UnprocessedItems?.[tableName] ?? []).map(
        u => u.PutRequest.Item,
      );
      if (unprocessed.length === 0) return [];
      if (attempt >= maxWriteRetries) return unprocessed;
      await sleep(jitteredBackoff(attempt));
      return writeChunkWithRetry(unprocessed, attempt + 1);
    } catch (err) {
      if (attempt >= maxWriteRetries) {
        logger.error(
          {err: err.message},
          'security-filter: osv -- batch write failed after retries',
        );
        return chunk;
      }
      await sleep(jitteredBackoff(attempt));
      return writeChunkWithRetry(chunk, attempt + 1);
    }
  }

  // Batches `items` into groups of BATCH_SIZE, writes groups in waves of
  // BATCH_CONCURRENCY concurrent BatchWriteCommands, and returns the flat
  // list of items that ultimately failed to write after retries.
  async function putItems(items) {
    const prefixed = items.map(item => ({...item, pk: keyFor(item.pk)}));
    const chunks = [];
    for (let i = 0; i < prefixed.length; i += BATCH_SIZE)
      chunks.push(prefixed.slice(i, i + BATCH_SIZE));

    const unwritten = [];
    for (let i = 0; i < chunks.length; i += BATCH_CONCURRENCY) {
      const wave = chunks.slice(i, i + BATCH_CONCURRENCY);
      await Promise.all(
        wave.map(async chunk => {
          unwritten.push(...(await writeChunkWithRetry(chunk)));
        }),
      );
    }
    return unwritten.map(stripPrefix);
  }

  async function close() {
    // The SDK's DynamoDBClient has no persistent connection that needs
    // explicit teardown (HTTP keep-alive sockets are pooled internally and
    // released on process exit) -- nothing to do here.
  }

  return {scanAll, getItem, putItem, putItems, deleteItem, close};
}

module.exports = {createDynamoDbStore};
