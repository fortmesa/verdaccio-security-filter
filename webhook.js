'use strict';

// Fires a single configured webhook for a security event. Deliberately
// minimal -- one static, operator-configured target (not a dynamic,
// admin-creatable list), so there's no SSRF surface, no retry queue, no
// per-subscription storage to build: config.yaml itself is the trust
// boundary, same as block:/allow: elsewhere in this plugin.
//
// Config shape (see docs/configuration.md's "Webhooks" section):
//   webhook:
//     url: https://example.com/hook
//     body: '{"pkg":"{{pkg}}"}'   # optional -- presence decides POST vs GET
//     any-other-key: value        # sent as an HTTP header, verbatim key
// `url`, `body`, and every header value are template strings: `{{name}}`
// is replaced with the matching field from the event data object.

const http = require('node:http');
const https = require('node:https');

const RESERVED_KEYS = new Set(['url', 'body']);

function substitute(template, data) {
  return String(template).replace(/\{\{(\w+)\}\}/g, (_match, key) =>
    data[key] === undefined || data[key] === null ? '' : String(data[key]),
  );
}

// Fire-and-forget: never throws, never blocks the caller on network I/O.
// `logger` is optional (malicious-packages.js's sync loop always has one;
// kept optional here so a unit test can omit it).
function sendWebhook(webhookConfig, data, logger) {
  if (!webhookConfig?.url) return;

  let url;
  try {
    url = new URL(substitute(webhookConfig.url, data));
  } catch (err) {
    logger?.error(
      {err: err.message},
      'security-filter: webhook -- invalid url after substitution, skipped',
    );
    return;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    logger?.error(
      {url: url.toString()},
      'security-filter: webhook -- unsupported url protocol, skipped',
    );
    return;
  }

  const body =
    webhookConfig.body !== undefined
      ? substitute(webhookConfig.body, data)
      : undefined;

  const headers = {};
  for (const [key, value] of Object.entries(webhookConfig)) {
    if (RESERVED_KEYS.has(key)) continue;
    headers[key] = substitute(value, data);
  }
  // Explicit Content-Length rather than letting Node fall back to chunked
  // transfer-encoding -- some webhook receivers (older/stricter HTTP
  // servers, some SIEM ingest endpoints) handle a fixed-length body more
  // reliably than a chunked one.
  if (body !== undefined) headers['Content-Length'] = Buffer.byteLength(body);

  const client = url.protocol === 'http:' ? http : https;
  const req = client.request(
    url,
    {method: body !== undefined ? 'POST' : 'GET', headers, timeout: 10_000},
    res => {
      res.resume(); // drain and discard -- nothing downstream reads the response
      if (res.statusCode >= 400) {
        logger?.warn(
          {url: url.toString(), status: res.statusCode},
          'security-filter: webhook -- delivery got a non-2xx/3xx response (@{status})',
        );
      }
    },
  );
  req.on('timeout', () => req.destroy(new Error('webhook request timed out')));
  req.on('error', err => {
    logger?.warn(
      {err: err.message, url: url.toString()},
      'security-filter: webhook -- delivery failed, ignored',
    );
  });
  if (body !== undefined) req.write(body);
  req.end();
}

module.exports = {sendWebhook};
