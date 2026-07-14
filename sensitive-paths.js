'use strict';

// Detects a lifecycle install script (preinstall/install/postinstall) that
// references a credential/config/auto-run path it has no legitimate reason to
// touch -- either directly, in its own command text, or indirectly, via a
// bundled script file it invokes (resolved from the published tarball's own
// contents -- see extractTarballFiles() below). See index.js's
// findSensitivePathTouch() for how the two checks here combine, and
// docs/configuration.md's "Sensitive path touch" section for the operator-
// facing config.
const tar = require('tar');

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
    files.push(match[0].replace(/^\.\//, ''));
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
  const parts = entryPath.split('/').filter(Boolean);
  return parts.slice(1).join('/');
}

// Streams a published tarball (already decoded to a Buffer from the publish
// request's own `_attachments` entry -- see index.js's getAttachmentBuffer())
// through node-tar's Parser, capturing only the entries whose normalized path
// is in `wantedRelativePaths` -- everything else is drained and discarded
// without ever being buffered in memory. gzip is auto-detected by node-tar's
// Parser itself (it sniffs the leading magic bytes on first write), so this
// works directly against the raw .tgz bytes with no separate zlib step.
function extractTarballFiles(tarballBuffer, wantedRelativePaths) {
  return new Promise((resolve, reject) => {
    const found = new Map();
    const parser = tar.list({
      onentry: entry => {
        const normalized = normalizeTarPath(entry.path);
        if (!wantedRelativePaths.has(normalized)) return; // drained regardless -- see tar's own onReadEntry wrapper
        const chunks = [];
        entry.on('data', chunk => chunks.push(chunk));
        entry.on('end', () =>
          found.set(normalized, Buffer.concat(chunks).toString('utf8')),
        );
      },
    });
    parser.on('error', reject);
    parser.on('end', () => resolve(found));
    parser.end(tarballBuffer);
  });
}

module.exports = {
  DEFAULT_SENSITIVE_PATHS,
  buildSensitivePathPattern,
  findDirectSensitivePathTouch,
  extractReferencedScriptFiles,
  findIndirectSensitivePathTouch,
  extractTarballFiles,
};
