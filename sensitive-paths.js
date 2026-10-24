'use strict';

// Detects a lifecycle install script (preinstall/install/postinstall) that
// references a credential/config/auto-run path it has no legitimate reason to
// touch -- either directly, in its own command text, or indirectly, via a
// bundled script file it invokes (resolved from the published tarball's own
// contents -- see extractTarballFiles() below). See index.js's
// findSensitivePathTouch() for how the two checks here combine, and
// docs/configuration.md's "Sensitive path touch" section for the operator-
// facing config.
const path = require('node:path');
const zlib = require('node:zlib');
const tar = require('tar');

// Limits on how much of a published tarball the indirect check will read.
// A publish body is at most max_body_size (10mb by default), but gzip
// inflates far past that, and every byte of it is read before the check
// can answer. Past any limit the tarball counts as unreadable (see
// index.js's findSensitivePathTouch()).
const TARBALL_LIMITS = {
  inflatedBytes: 256 * 1024 * 1024,
  entries: 100000,
  fileBytes: 8 * 1024 * 1024,
};

const GZIP_MAGIC = Buffer.from([0x1f, 0x8b]);
const ZSTD_MAGIC = Buffer.from([0x28, 0xb5, 0x2f, 0xfd]);

// Dot-prefixed credential/config/history/auto-run directories and files a
// package's own install script never has a legitimate reason to read from or
// write to. Covers cloud/SSH/registry credentials, local secret stores, shell
// history, and editor/agent auto-run config surfaces (a compromised install
// script planting a .vscode/tasks.json or .claude/settings.json hook is a real
// supply-chain technique, not just a credential-theft one). Overridable via
// sensitivePaths.paths in config.
const DEFAULT_SENSITIVE_PATHS = [
  '.ssh',
  '.npmrc',
  '.yarnrc',
  '.yarnrc.yml',
  '.aws',
  '.azure',
  '.config/gcloud',
  '.terraform.d',
  '.bitcoin',
  '.docker',
  '.dropbox',
  '.gemini',
  '.kube',
  '.mongodb',
  '.bash_history',
  '.zsh_history',
  '.vscode/tasks.json',
  '.claude',
  '.antigravity',
  '.cursor',
];

// Local-script-file-shaped tokens worth resolving out of an install command's
// own text -- an install script commonly just dispatches to a bundled file
// (`node scripts/setup.js`) rather than doing everything inline; see
// extractReferencedScriptFiles() below.
const SCRIPT_FILE_PATTERN = /[\w./-]+\.(?:js|cjs|mjs|ts|sh|bash|py|rb|pl)\b/g;

function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Negative lookbehind: a hit must not be immediately preceded by another word
// character or `.` -- rules out a coincidental substring inside an unrelated
// identifier/filename (e.g. "myapp.aws.json") while still matching the real,
// path-shaped forms these entries actually appear in ("~/.aws/credentials",
// "'.aws'", "/root/.ssh/id_rsa").
function buildSensitivePathPattern(paths) {
  const alternation = paths.map(escapeRegExp).join('|');
  return new RegExp(`(?<![\\w.])(?:${alternation})`, 'i');
}

// Direct: does the lifecycle script's own command text reference a sensitive path?
function findDirectSensitivePathTouch(command, paths) {
  if (typeof command !== 'string' || command.length === 0) return null;
  const match = buildSensitivePathPattern(paths).exec(command);
  return match ? match[0] : null;
}

// A path inside the package, the way npm resolves it: "./scripts//a.js",
// "scripts/../scripts/a.js" and "scripts/a.js" are one file, and the tar
// entry and the install command have to agree on its name to be compared.
function normalizePackagePath(filePath) {
  const normalized = path.posix.normalize(filePath).replace(/^(?:\.\/)+/, '');
  return normalized === '.' ? '' : normalized;
}

// Extracts local script-file-shaped tokens referenced by a lifecycle command --
// skips anything that's actually part of a URL (a curl/wget target ending in
// .sh is already covered by index.js's own shell-pipe/network-call
// heuristics, not by this file-content check, which only ever looks at files
// bundled in the tarball itself).
function extractReferencedScriptFiles(command) {
  if (typeof command !== 'string') return [];
  const files = [];
  SCRIPT_FILE_PATTERN.lastIndex = 0;
  let match;
  while ((match = SCRIPT_FILE_PATTERN.exec(command))) {
    const precedingText = command.slice(0, match.index);
    if (/:\/\/[^\s]*$/.test(precedingText)) continue; // part of a URL, not a local file
    files.push(normalizePackagePath(match[0]));
  }
  return files;
}

// Indirect: does any local script file the command actually invokes -- already
// resolved into `tarballFiles` (Map<relativePath, content>, built by
// extractTarballFiles() below, scoped to just the files
// extractReferencedScriptFiles() found across every version being checked) --
// itself reference a sensitive path? `tarballFiles` is null/empty outside of a
// real publish (filter_metadata has no tarball to inspect), in which case this
// always returns null and only the direct check above ever fires.
function findIndirectSensitivePathTouch(command, tarballFiles, paths) {
  if (!tarballFiles || tarballFiles.size === 0) return null;
  const pattern = buildSensitivePathPattern(paths);
  for (const file of extractReferencedScriptFiles(command)) {
    const content = tarballFiles.get(file);
    if (content == null) continue;
    const match = pattern.exec(content);
    if (match) return {file, matched: match[0]};
  }
  return null;
}

// Every tar entry is prefixed with the tarball's own single top-level
// directory (npm's long-standing "package/" packing convention) -- stripped
// here so callers can key `wantedRelativePaths` by the plain in-package path
// (e.g. "scripts/setup.js") without needing to know or guess that prefix.
function normalizeTarPath(entryPath) {
  const parts = normalizePackagePath(entryPath).split('/').filter(Boolean);
  return parts.slice(1).join('/');
}

function limitError(message) {
  return Object.assign(new Error(message), {code: 'TARBALL_LIMIT'});
}

function startsWith(buffer, magic) {
  return (
    buffer.length >= magic.length &&
    buffer.subarray(0, magic.length).equals(magic)
  );
}

function isPlainTar(buffer) {
  return (
    buffer.length >= 512 && buffer.toString('latin1', 257, 262) === 'ustar'
  );
}

// Reads a published tarball (already decoded to a Buffer from the publish
// request's own `_attachments` entry -- see index.js's getAttachmentBuffer())
// and returns {files: Map<path, content>, links: Set<path>} for the entries
// whose normalized path is in `wantedRelativePaths`; everything else is
// drained and discarded without being kept. A wanted path the tarball holds
// as a symbolic or hard link lands in `links`, since its content isn't in
// the tarball to read. gzip is inflated here, with node:zlib, so the
// inflated size can be counted against TARBALL_LIMITS; node-tar's parser
// only ever sees plain tar, so it never decompresses anything itself (a
// compressed stream inside the gzip is refused). Rejects past any limit,
// and for anything that is neither gzip nor tar.
function extractTarballFiles(
  tarballBuffer,
  wantedRelativePaths,
  limits = TARBALL_LIMITS,
) {
  return new Promise((resolve, reject) => {
    const files = new Map();
    const links = new Set();
    let entries = 0;
    let settled = false;
    let gunzip = null;
    const fail = err => {
      if (settled) return;
      settled = true;
      gunzip?.destroy();
      reject(err);
    };

    const parser = tar.list({
      onReadEntry: entry => {
        if (settled) return;
        entries += 1;
        if (entries > limits.entries) {
          fail(
            limitError(`the tarball has more than ${limits.entries} entries`),
          );
          return;
        }
        const normalized = normalizeTarPath(entry.path);
        if (!wantedRelativePaths.has(normalized)) return; // drained regardless -- see tar's own onReadEntry wrapper
        if (entry.type === 'SymbolicLink' || entry.type === 'Link') {
          links.add(normalized);
          return;
        }
        const chunks = [];
        let size = 0;
        entry.on('data', chunk => {
          size += chunk.length;
          if (size > limits.fileBytes) {
            fail(
              limitError(
                `${normalized} is larger than ${limits.fileBytes} bytes`,
              ),
            );
            return;
          }
          chunks.push(chunk);
        });
        entry.on('end', () => {
          if (!settled)
            files.set(normalized, Buffer.concat(chunks).toString('utf8'));
        });
      },
    });
    parser.on('error', fail);
    parser.on('end', () => {
      if (settled) return;
      settled = true;
      resolve({files, links});
    });

    if (startsWith(tarballBuffer, GZIP_MAGIC)) {
      gunzip = zlib.createGunzip();
      let inflated = 0;
      // The first few inflated bytes are held back until there are enough
      // to tell whether they start another compressed stream, whatever
      // sizes zlib happens to emit them in.
      let head = Buffer.alloc(0);
      const release = () => {
        if (startsWith(head, GZIP_MAGIC) || startsWith(head, ZSTD_MAGIC)) {
          fail(new Error('the tarball is compressed more than once'));
          return false;
        }
        parser.write(head);
        head = null;
        return true;
      };
      gunzip.on('data', chunk => {
        if (settled) return;
        inflated += chunk.length;
        if (inflated > limits.inflatedBytes) {
          fail(
            limitError(
              `the tarball inflates past ${limits.inflatedBytes} bytes`,
            ),
          );
          return;
        }
        if (head === null) {
          parser.write(chunk);
          return;
        }
        head = Buffer.concat([head, chunk]);
        if (head.length >= ZSTD_MAGIC.length) release();
      });
      gunzip.on('end', () => {
        if (settled) return;
        if (head !== null && !release()) return;
        parser.end();
      });
      gunzip.on('error', fail);
      gunzip.end(tarballBuffer);
    } else if (isPlainTar(tarballBuffer)) {
      parser.end(tarballBuffer);
    } else {
      fail(new Error('the attachment is neither a gzip nor a tar archive'));
    }
  });
}

module.exports = {
  DEFAULT_SENSITIVE_PATHS,
  TARBALL_LIMITS,
  normalizePackagePath,
  buildSensitivePathPattern,
  findDirectSensitivePathTouch,
  extractReferencedScriptFiles,
  findIndirectSensitivePathTouch,
  extractTarballFiles,
};
