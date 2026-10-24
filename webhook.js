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
//
// Several fields (pkg, ver, reason, ...) carry text a publisher chose, so
// every substituted value has its control characters removed, and is then
// encoded for where it lands: URL-encoded in `url`, JSON-escaped in a
// `body` that is a JSON template (a `{"text":"{{reason}}"}` Slack body
// stays one string field whatever the value holds), and left as is in a
// header (Node itself refuses a header value with CR or LF in it).

const http = require('node:http');
const https = require('node:https');

const RESERVED_KEYS = new Set(['url', 'body']);
const PLACEHOLDER = /\{\{(\w+)\}\}/g;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/g;

function fieldText(data, key) {
  const value = data[key];
  if (value === undefined || value === null) return '';
  return String(value).replace(CONTROL_CHARS, '');
}

function substitute(template, data, encode = text => text) {
  return String(template).replace(PLACEHOLDER, (_match, key) =>
    encode(fieldText(data, key)),
  );
}

// A body template that is valid JSON once every placeholder stands for an
// ordinary string. Placeholders are then filled with JSON-escaped text.
function isJsonTemplate(template) {
  try {
    JSON.parse(String(template).replace(PLACEHOLDER, 'x'));
    return true;
  } catch {
    return false;
  }
}

function jsonEscape(text) {
  return JSON.stringify(text).slice(1, -1);
}

// Fire-and-forget: never throws, never blocks the caller on network I/O.
// `logger` is optional (malicious-packages.js's sync loop always has one;
// kept optional here so a unit test can omit it).
function sendWebhook(webhookConfig, data, logger) {
  if (!webhookConfig?.url) return;

  let url;
  try {
    url = new URL(substitute(webhookConfig.url, data, encodeURIComponent));
  } catch (err) {
    logger?.error(
      {err: err.message},
      'security-filter: webhook -- invalid url after substitution, skipped',
    );
    return;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    logger?.error(
      {protocol: url.protocol, host: url.host},
      'security-filter: webhook -- unsupported url protocol, skipped',
    );
    return;
  }

  const body =
    webhookConfig.body !== undefined
      ? substitute(
          webhookConfig.body,
          data,
          isJsonTemplate(webhookConfig.body) ? jsonEscape : undefined,
        )
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
  let req;
  try {
    // Node validates header values synchronously here and throws
    // (TypeError [ERR_INVALID_CHAR]) if a substituted field (pkg/ver/reason/
    // etc. -- any of which can carry attacker-controlled bytes, e.g. a raw
    // CR/LF smuggled through a crafted package name or version key) put a
    // CR or LF into a header value. Caught the same way an invalid `url`
    // already is above: log and skip this one delivery, never crash the
    // process over a malformed webhook payload.
    req = client.request(
      url,
      {method: body !== undefined ? 'POST' : 'GET', headers, timeout: 10_000},
      res => {
        res.resume(); // drain and discard -- nothing downstream reads the response
        if (res.statusCode >= 400) {
          logger?.warn(
            {host: url.host, status: res.statusCode},
            'security-filter: webhook -- delivery got a non-2xx/3xx response (@{status})',
          );
        }
      },
    );
  } catch (err) {
    logger?.error(
      {err: err.message},
      'security-filter: webhook -- invalid header value after substitution, skipped',
    );
    return;
  }
  req.on('timeout', () => req.destroy(new Error('webhook request timed out')));
  req.on('error', err => {
    logger?.warn(
      {err: err.message, host: url.host},
      'security-filter: webhook -- delivery failed, ignored',
    );
  });
  if (body !== undefined) req.write(body);
  req.end();
}

module.exports = {sendWebhook};
