'use strict';

// Installs and caches real npm (8 through whatever "latest" resolves to
// today) and real yarn classic (1.x) binaries on demand, for tests that need
// to drive an actual client CLI against a throwaway registry instead of
// simulating its wire protocol with raw fetch() calls. Yarn Berry (4.x)
// doesn't need anything from here -- it's already corepack-managed via each
// throwaway project's own `packageManager` field.
//
// This file is intentionally duplicated identically across
// fm-npmjs/test/, verdaccio-attestations/test/, and
// verdaccio-security-filter/test/ -- same convention as .prettierrc/
// .yarnrc.yml being copied across the plugin repos: each repo's test suite
// is fully standalone, no shared internal package.

const {execFileSync} = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

// One major version per npm release line actually in wide use today --
// protocol-relevant behavior changes at major boundaries, not patches.
// 5 and 6 included specifically to exercise the older
// /-/npm/v1/security/audits(/quick) protocol (see getNodeBinaryForNpm()
// below for why npm 5 needs special handling to even run at all). 7 is its
// own real boundary too, but a softer one -- traced directly in its own
// @npmcli/arborist source: it tries advisories/bulk FIRST and only falls
// back to audits/quick if that request itself fails, whereas 6 and below
// have no concept of advisories/bulk at all and only ever call
// audits/quick directly.
const NPM_VERSIONS = ['5', '6', '7', '8', '9', '10', '11'];

const CACHE_ROOT = path.join(os.tmpdir(), 'fm-npmjs-cli-matrix-cache');

// npm 5 does not merely print a deprecation notice on a modern Node runtime
// -- confirmed via a real `npm install` that it actually crashes
// (`cb.apply is not a function`), a genuine incompatibility, not a cosmetic
// warning. npm 6 was verified to run a real install successfully on a
// modern Node (deprecation warnings only), so it needs no override.
// '10.24.1' is npm 5's own newest self-declared supported Node release
// ("Supported releases of Node.js are the latest release of 4, 6, 7, 8, 9,
// 10"), confirmed via a real install to actually work. Not installed by
// this file -- assumes the environment already has it via nvm (`nvm
// install 10.24.1`), the same assumption this file already makes about a
// system `npm` being available to bootstrap ensureInstalled() itself.
const NODE_VERSION_OVERRIDE = {5: '10.24.1'};

function getNodeBinaryForNpm(npmMajorVersion) {
  const override = NODE_VERSION_OVERRIDE[npmMajorVersion];
  if (!override) return process.execPath;
  const nvmDir = process.env.NVM_DIR || path.join(os.homedir(), '.nvm');
  const binPath = path.join(
    nvmDir,
    'versions',
    'node',
    `v${override}`,
    'bin',
    'node',
  );
  if (!fs.existsSync(binPath)) {
    throw new Error(
      `npm ${npmMajorVersion} needs Node ${override} via nvm, but ${binPath} doesn't exist -- run \`nvm install ${override}\` first`,
    );
  }
  return binPath;
}

function ensureInstalled(cacheDir, spec, binRelPath) {
  const binPath = path.join(cacheDir, binRelPath);
  if (fs.existsSync(binPath)) return binPath;
  fs.mkdirSync(cacheDir, {recursive: true});
  execFileSync(
    process.platform === 'win32' ? 'npm.cmd' : 'npm',
    [
      'install',
      '--prefix',
      cacheDir,
      spec,
      '--silent',
      '--no-audit',
      '--no-fund',
    ],
    {stdio: 'pipe'},
  );
  if (!fs.existsSync(binPath)) {
    throw new Error(
      `expected ${spec} to install a binary at ${binPath}, but it didn't`,
    );
  }
  return binPath;
}

// Returns an absolute path to that major version's npm-cli.js entry point --
// invoke via `node <path> <args>`, not directly (no shebang reliance, works
// identically on every platform).
function getNpmBinary(majorVersion) {
  const cacheDir = path.join(CACHE_ROOT, `npm-${majorVersion}`);
  return ensureInstalled(
    cacheDir,
    `npm@${majorVersion}`,
    path.join('node_modules', 'npm', 'bin', 'npm-cli.js'),
  );
}

function getYarnClassicBinary() {
  const cacheDir = path.join(CACHE_ROOT, 'yarn-classic');
  return ensureInstalled(
    cacheDir,
    'yarn@1.22.22',
    path.join('node_modules', 'yarn', 'bin', 'yarn.js'),
  );
}

// Runs `node <entryJs> ...args` in `cwd`, with `env` merged over the
// current process env (so a caller can point registry/auth config at a
// throwaway registry via env vars without touching global config).
// `nodeBin` defaults to the Node running this test process itself --
// override it (see getNodeBinaryForNpm() above) for an npm major that
// can't actually run there. Returns {status, stdout, stderr} instead of
// throwing on a non-zero exit -- callers assert on `status` themselves,
// since "the CLI exited non-zero" is itself sometimes the exact behavior
// under test (e.g. a rejected publish).
function runNode(entryJs, args, {cwd, env = {}, nodeBin = process.execPath}) {
  const result = require('node:child_process').spawnSync(
    nodeBin,
    [entryJs, ...args],
    {
      cwd,
      env: {...process.env, ...env},
      encoding: 'utf8',
    },
  );
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

module.exports = {
  NPM_VERSIONS,
  getNpmBinary,
  getYarnClassicBinary,
  getNodeBinaryForNpm,
  runNode,
};
