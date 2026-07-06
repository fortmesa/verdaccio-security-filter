'use strict';

// Drives REAL npm (8/9/10/11) and REAL yarn (classic 1.x, berry 4.x) client
// binaries against a real running verdaccio process with THIS plugin's
// current local code loaded (via a symlink into a throwaway node_modules --
// see setupPluginSymlink() below), not a stale last-published version and
// not hand-constructed like the other test/smoke-*.js files do. Every
// scenario below runs against EVERY client variant, not just one -- a
// client's own quirks (exact request shape, error/exit-code handling,
// audit command differences) can differ per major version, and only
// happen to be caught by testing all of them, not just the newest.
//
// Run with:
//   yarn install && node test/cli-real.js
// (separate from `yarn test` -- this installs 4 extra npm versions + yarn
// classic on first run, caching them under the OS tmp dir.)

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawn, spawnSync} = require('node:child_process');
const {
  NPM_VERSIONS,
  getNpmBinary,
  getYarnClassicBinary,
  getNodeBinaryForNpm,
  runNode,
} = require('./cli-matrix');

const PLUGIN_ROOT = path.join(__dirname, '..');
const WORKDIR = fs.mkdtempSync(
  path.join(os.tmpdir(), 'security-filter-cli-real-'),
);
const STORAGE_DIR = path.join(WORKDIR, 'storage');
const HTPASSWD_FILE = path.join(WORKDIR, 'htpasswd');
const CONFIG_FILE = path.join(WORKDIR, 'config.yaml');
const PLUGINS_DIR = path.join(WORKDIR, 'plugins-node_modules');
// Reassigned between phases (see runReplaceStrategyPhase()) -- every helper
// below reads it at call time via closure, not at client-creation time, so
// swapping it (and `token`) between two sequential registry instances is
// safe as long as nothing runs concurrently across phases.
let REGISTRY_URL = 'http://127.0.0.1:4881';

// Mixed into every package name this file publishes -- npm/yarn clients
// cache a tarball by name+version in a persistent, cross-run local cache,
// on the reasonable general assumption that a given name+version is
// immutable content. Reusing the same literal names across repeated runs
// of this file (each against a fresh, unrelated throwaway registry) defeats
// that assumption and serves stale cached content instead of actually
// fetching from the current run's server -- confirmed by hand when a
// marker-format change wasn't reflected in an install until this was added.
const RUN_ID = crypto.randomBytes(4).toString('hex');

let token; // set once in main(), read by every client factory below

let passed = 0;
const results = [];
async function check(name, fn) {
  try {
    await fn();
    passed += 1;
    results.push(`PASS: ${name}`);
  } catch (err) {
    results.push(`FAIL: ${name}`);
    results.push(err.stack || err.message);
  }
}

// Symlinks this repo's own root into a throwaway node_modules/@fortmesa/ so
// Verdaccio's real require()-based plugin loader finds the CURRENT local
// code -- Node resolves a symlinked module's own require() calls against
// its real (target) path, so this plugin's already-installed own
// node_modules (semver, minimatch, body-parser, ...) resolve normally.
function setupPluginSymlink() {
  const scopeDir = path.join(PLUGINS_DIR, '@fortmesa');
  fs.mkdirSync(scopeDir, {recursive: true});
  fs.symlinkSync(
    PLUGIN_ROOT,
    path.join(scopeDir, 'verdaccio-security-filter'),
    'dir',
  );
}

async function waitForUp(url, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      // not up yet
    }
    await new Promise(r => setTimeout(r, 200));
  }
  throw new Error(`verdaccio never came up at ${url}`);
}

function startVerdaccio(configPath, port) {
  const bin = path.join(PLUGIN_ROOT, 'node_modules', '.bin', 'verdaccio');
  const proc = spawn(bin, ['--config', configPath, '--listen', String(port)], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  proc.stdout.on('data', d => (output += d));
  proc.stderr.on('data', d => (output += d));
  proc.getOutput = () => output;
  return proc;
}

async function registerUser(username) {
  const res = await fetch(
    `${REGISTRY_URL}/-/user/org.couchdb.user:${username}`,
    {
      method: 'PUT',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({
        name: username,
        password: 'throwaway-pw',
        type: 'user',
        roles: [],
        date: new Date(0).toISOString(),
      }),
    },
  );
  const body = await res.json();
  if (!body.token)
    throw new Error(`user registration failed: ${JSON.stringify(body)}`);
  return body.token;
}

function makeProjectDir(name, version, deps) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'proj-'));
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({name, version, main: 'index.js', dependencies: deps ?? {}}),
  );
  fs.writeFileSync(
    path.join(dir, 'index.js'),
    `module.exports = ${JSON.stringify({marker: `${name}@${version}`})};\n`,
  );
  return dir;
}

function writeNpmrc(dir) {
  const {host} = new URL(REGISTRY_URL);
  fs.writeFileSync(
    path.join(dir, '.npmrc'),
    [
      `registry=${REGISTRY_URL}/`,
      `//${host}/:_authToken=${token}`,
      'always-auth=true',
    ].join('\n') + '\n',
  );
}

// npmPreapprovedPackages bypasses yarn's "minimal age gate" quarantine on
// freshly-published packages -- but that quarantine feature (and this
// config key) only exists in yarn 4.x. Confirmed directly (`yarn config -v`
// on real 2.4.3 and 3.8.7): neither lists it, and yarn 4.x itself hard-
// rejects an unrecognized config key at startup ("Unrecognized or legacy
// configuration settings found"), so this can't just be included
// unconditionally for every Berry major -- 2.x/3.x never quarantine
// freshly-published packages at all, so there's nothing to bypass there.
function writeYarnBerryRc(dir, version) {
  const needsPreapproval = Number(version.split('.')[0]) >= 4;
  fs.writeFileSync(
    path.join(dir, '.yarnrc.yml'),
    [
      'nodeLinker: node-modules',
      `npmRegistryServer: '${REGISTRY_URL}'`,
      'npmAlwaysAuth: true',
      `npmAuthToken: '${token}'`,
      'unsafeHttpWhitelist:',
      '  - 127.0.0.1',
      ...(needsPreapproval
        ? [
            'npmPreapprovedPackages:',
            "  - 'cli-real-*'",
            "  - 'replace-test-*'",
          ]
        : []),
    ].join('\n') + '\n',
  );
  fs.writeFileSync(path.join(dir, 'yarn.lock'), '');
}

function setYarnBerryPackageManager(dir, version) {
  const pkgJsonPath = path.join(dir, 'package.json');
  const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
  pkgJson.packageManager = `yarn@${version}`;
  fs.writeFileSync(pkgJsonPath, JSON.stringify(pkgJson));
}

// --- one client object per variant, same {name, setup, publish, install,
// audit} shape regardless of which real binary/config format it needs
// underneath, so every scenario below can just loop over ALL of them. ---

function makeNpmClient(majorVersion) {
  const bin = getNpmBinary(majorVersion);
  // Only npm 5 actually needs this (see cli-matrix.js's
  // NODE_VERSION_OVERRIDE) -- everything else still runs under the same
  // Node running this test process, unchanged.
  const nodeBin = getNodeBinaryForNpm(majorVersion);
  const npmArgs = extra => ['--registry', REGISTRY_URL, ...extra];
  const opts = dir => ({
    cwd: dir,
    env: {npm_config_userconfig: path.join(dir, '.npmrc')},
    nodeBin,
  });
  return {
    name: `npm@${majorVersion}`,
    majorVersion,
    // Confirmed via real testing: npm 6 has no concept of advisories/bulk
    // at all -- only ever calls /-/npm/v1/security/audits(/quick), now
    // served by legacy-audit.js. npm 7 traces (in its own @npmcli/arborist
    // source) trying advisories/bulk FIRST and only falling back to
    // audits/quick if that request itself fails -- since this plugin's
    // bulk route succeeds, 7+ never needs the fallback.
    usesLegacyAudit: majorVersion === '6',
    // Confirmed via real testing (a live npm 8 install/audit round-trip
    // against a seeded advisory): npm 7 and npm 8's own `npm audit`
    // -- with or without --json -- never set a non-zero exit code, even
    // though the JSON/text report itself correctly lists the real
    // vulnerability. npm 9+ sets it correctly for the identical report
    // shape. This is a genuine upstream npm bug in those two versions,
    // not something this plugin's response can influence -- the report
    // CONTENT is still asserted on for these clients, just not the exit
    // code.
    auditExitCodeUnreliable: majorVersion === '7' || majorVersion === '8',
    setup: writeNpmrc,
    publish: dir => runNode(bin, ['publish', ...npmArgs([])], opts(dir)),
    install: dir => runNode(bin, ['install', ...npmArgs([])], opts(dir)),
    // npm 5 predates `npm audit` entirely (added in 6.1.0) -- callers that
    // loop over every client's .audit() need to account for that gap
    // themselves; this client object doesn't paper over it.
    audit: dir => runNode(bin, ['audit', ...npmArgs(['--json'])], opts(dir)),
    // Installs one exact spec without touching an already-wide-enough
    // declared range in package.json (e.g. `^1.0.0` permits 1.1.0, but
    // this still resolves/pins the vulnerable 1.0.0 for a later `audit
    // fix` to have something real to upgrade) -- runAuditFixPhase's only
    // consumer.
    installExact: (dir, spec) =>
      runNode(bin, ['install', spec, ...npmArgs([])], opts(dir)),
    auditFix: dir => runNode(bin, ['audit', 'fix', ...npmArgs([])], opts(dir)),
  };
}

function makeYarnClassicClient() {
  const bin = getYarnClassicBinary();
  return {
    name: 'yarn classic (1.x)',
    // Confirmed via real testing (`yarn audit --verbose`): yarn classic's
    // audit command hardcodes its POST target to the real
    // https://registry.yarnpkg.com/-/npm/v1/security/audits -- the
    // --registry flag / configured registry is completely ignored for
    // this one command. Not a wire-protocol difference like npm 6/yarn
    // 2.x/3.x below (those at least ask OUR server, just via an older
    // route, now served by legacy-audit.js) -- this plugin's OSV data can
    // never reach yarn classic's `yarn audit` at all, no matter what's
    // implemented here. auditUnreachable (not usesLegacyAudit) is the flag
    // the coverage loops below actually filter on, precisely to keep this
    // "can never work" case distinct from "uses the older protocol, which
    // this plugin does now serve".
    usesLegacyAudit: true,
    auditUnreachable: true,
    setup: writeNpmrc, // yarn classic reads the same .npmrc format
    publish: dir => {
      // yarn classic's `publish` always BUMPS the version via --new-version
      // before publishing -- reading the target version back out of the
      // directory's own package.json (rather than hardcoding one) is
      // required as soon as a test publishes more than one version of the
      // same package (a hardcoded value would re-bump an already-published
      // version and collide).
      const {version} = JSON.parse(
        fs.readFileSync(path.join(dir, 'package.json'), 'utf8'),
      );
      return runNode(
        bin,
        [
          'publish',
          '--registry',
          REGISTRY_URL,
          '--new-version',
          version,
          '--no-git-tag-version',
        ],
        {cwd: dir},
      );
    },
    install: dir =>
      runNode(bin, ['install', '--registry', REGISTRY_URL], {cwd: dir}),
    audit: dir =>
      runNode(bin, ['audit', '--registry', REGISTRY_URL], {cwd: dir}),
  };
}

// Covers yarn 2.x/3.x/4.x uniformly -- all three are the same "Berry"
// architecture/CLI protocol (a from-scratch rewrite from yarn classic),
// corepack-managed via each project's own packageManager field rather than
// installed as a versioned npm package the way classic/npm are. Versions
// below are each major's latest stable release, confirmed to actually
// resolve via corepack (it downloads the real release from
// repo.yarnpkg.com on first use, cached by corepack itself afterward).
function makeYarnBerryClient(version, label) {
  return {
    name: `yarn ${label} (${version})`,
    // Confirmed via real testing: yarn 2.x/3.x's own `yarn npm audit` never
    // even attempts advisories/bulk -- 3.8.7 hits
    // /-/npm/v1/security/audits/quick directly (visible in its own error
    // output), and 2.4.3 the same way. Only 4.x actually calls
    // advisories/bulk. Both routes are real now (see legacy-audit.js), so
    // this no longer means "untestable" -- just "exercises the other
    // route".
    usesLegacyAudit: Number(version.split('.')[0]) < 4,
    setup: dir => writeYarnBerryRc(dir, version),
    publish(dir) {
      setYarnBerryPackageManager(dir, version);
      const pre = spawnSync('yarn', ['install'], {cwd: dir, encoding: 'utf8'});
      if (pre.status !== 0) return pre;
      return spawnSync('yarn', ['npm', 'publish'], {
        cwd: dir,
        encoding: 'utf8',
      });
    },
    install(dir) {
      setYarnBerryPackageManager(dir, version);
      return spawnSync('yarn', ['install'], {cwd: dir, encoding: 'utf8'});
    },
    audit: dir =>
      spawnSync('yarn', ['npm', 'audit'], {cwd: dir, encoding: 'utf8'}),
  };
}

async function main() {
  setupPluginSymlink();

  const config = `
storage: ${STORAGE_DIR}
plugins: ${PLUGINS_DIR}

auth:
  htpasswd:
    file: ${HTPASSWD_FILE}
    max_users: 1000

packages:
  '**':
    access: $authenticated
    publish: $authenticated

filters:
  '@fortmesa/verdaccio-security-filter':
    packageAge:
      minDays: 0
    block:
      - '@blocked/*'

middlewares:
  '@fortmesa/verdaccio-security-filter':
    blockPublishMatches: true

log:
  type: stdout
  format: pretty
  level: warn
`;
  fs.mkdirSync(path.dirname(HTPASSWD_FILE), {recursive: true});
  fs.writeFileSync(HTPASSWD_FILE, '');
  fs.mkdirSync(STORAGE_DIR, {recursive: true});
  fs.writeFileSync(CONFIG_FILE, config);

  const proc = startVerdaccio(CONFIG_FILE, 4881);
  try {
    await waitForUp(`${REGISTRY_URL}/-/ping`);
    token = await registerUser('cli-real-tester');

    const clients = [
      ...NPM_VERSIONS.map(makeNpmClient),
      makeYarnClassicClient(),
      // Latest stable release of each Berry major, confirmed to resolve
      // via corepack -- see makeYarnBerryClient()'s own comment for why
      // these three (not just the newest) matter.
      makeYarnBerryClient('2.4.3', 'berry'),
      makeYarnBerryClient('3.8.7', 'berry'),
      makeYarnBerryClient('4.17.0', 'berry'),
    ];

    // === plugin loading via Verdaccio's own real loader ===
    await check(
      'verdaccio boots with the current local plugin code loaded via its own loader',
      async () => {
        const res = await fetch(`${REGISTRY_URL}/-/ping`);
        assert.equal(res.status, 200);
      },
    );

    // === every client: plain publish + install round-trip ===
    for (const client of clients) {
      await check(
        `${client.name}: real publish + real install round-trip`,
        () => {
          const slug = client.name.replace(/[^a-z0-9]+/gi, '-');
          const pkgName = `cli-real-${RUN_ID}-${slug}-secfilter-pkg`;
          const pubDir = makeProjectDir(pkgName, '1.0.0');
          client.setup(pubDir);
          const publish = client.publish(pubDir);
          assert.equal(
            publish.status,
            0,
            `publish failed:\n${publish.stdout}\n${publish.stderr}`,
          );

          const installDir = makeProjectDir('consumer', '1.0.0', {
            [pkgName]: '1.0.0',
          });
          client.setup(installDir);
          const install = client.install(installDir);
          assert.equal(
            install.status,
            0,
            `install failed:\n${install.stdout}\n${install.stderr}`,
          );
          const installed = require(
            path.join(installDir, 'node_modules', pkgName, 'index.js'),
          );
          assert.equal(installed.marker, `${pkgName}@1.0.0`);
        },
      );
    }

    // === every client: publish of a block:-matched package is genuinely rejected ===
    for (const client of clients) {
      await check(
        `${client.name}: publish of a block:-matched package is rejected with a non-zero exit`,
        () => {
          const slug = client.name.replace(/[^a-z0-9]+/gi, '-');
          const pkgName = `blocked-pkg-${RUN_ID}-${slug}`;
          // Scoped to this client so 6 variants don't collide on one name --
          // the shared block: rule below matches the whole '@blocked/*' scope.
          const pubDir = makeProjectDir(`@blocked/${pkgName}`, '1.0.0');
          client.setup(pubDir);
          const publish = client.publish(pubDir);
          assert.notEqual(
            publish.status,
            0,
            'a real publish must fail for a block:-matched package',
          );

          const installDir = makeProjectDir('consumer', '1.0.0', {
            [`@blocked/${pkgName}`]: '1.0.0',
          });
          client.setup(installDir);
          const install = client.install(installDir);
          assert.notEqual(
            install.status,
            0,
            'a rejected publish must never actually land in storage -- a real install must also fail',
          );
        },
      );
    }

    // === every client that HAS an audit command: a package with no known advisories gets a clean empty response, not a crash ===
    // (regression coverage for a real bug found by hand: with no
    // advisories/bulk route at all, npm's own `npm audit` degrades
    // gracefully on the resulting 404, but yarn berry 4.x's `yarn npm
    // audit` throws an uncaught exception and dumps a raw stack trace
    // instead. register_middlewares()'s real advisories/bulk and
    // audits(/quick) routes always avoid that regardless of whether they
    // have anything to report -- this package name is never seeded with
    // OSV data, so the real, non-empty-response case is covered separately
    // below.)
    // npm 5 predates `npm audit` entirely (added in 6.1.0) -- there's no
    // command to even invoke, so it's excluded here, not silently expected
    // to behave like the others. yarn classic is excluded for the
    // DIFFERENT, permanent reason on its own auditUnreachable comment
    // above (hardcoded external registry target -- no route this plugin
    // registers can ever be reached). npm 6 and yarn 2.x/3.x are included
    // here despite usesLegacyAudit -- they use the older
    // /-/npm/v1/security/audits(/quick) protocol, but that's real now too
    // (see legacy-audit.js).
    for (const client of clients.filter(
      c => c.majorVersion !== '5' && !c.auditUnreachable,
    )) {
      await check(
        `${client.name}: audit of a package with no known advisories gets a clean empty response, not a crash`,
        () => {
          const slug = client.name.replace(/[^a-z0-9]+/gi, '-');
          const pkgName = `cli-real-audit-${RUN_ID}-${slug}-pkg`;
          const dir = makeProjectDir(pkgName, '1.0.0');
          client.setup(dir);
          const publish = client.publish(dir);
          assert.equal(
            publish.status,
            0,
            `publish failed:\n${publish.stdout}\n${publish.stderr}`,
          );
          const install = client.install(dir);
          assert.equal(
            install.status,
            0,
            `install (lockfile) failed:\n${install.stdout}\n${install.stderr}`,
          );

          const audit = client.audit(dir);
          assert.equal(
            audit.status,
            0,
            `expected a clean "no advisories" result, not a crash:\n${audit.stdout}\n${audit.stderr}`,
          );
          assert.doesNotMatch(
            audit.stdout + audit.stderr,
            /RequestError|HTTPError|Response code 404/,
            'must not surface the raw HTTP client error yarn used to crash with on a 404',
          );
        },
      );
    }

    await runReplaceStrategyPhase(clients);
    await runRealAdvisoryPhase(clients);
    await runAuditFixPhase(clients);

    console.log(results.join('\n'));
    console.log(`\n${passed} check(s) passed.`);
    if (results.some(r => r.startsWith('FAIL'))) process.exitCode = 1;
  } finally {
    proc.kill();
    if (process.exitCode) {
      console.error('\n--- verdaccio process output ---');
      console.error(proc.getOutput());
    }
    fs.rmSync(WORKDIR, {recursive: true, force: true});
  }
}

// Separate registry instance, deliberately WITHOUT blockPublishMatches:
// strategy is ignored entirely at publish time (see index.js's own
// publish-gate comments) -- with the gate on, publishing the "to be
// replaced" version would be rejected outright before it ever reached
// storage, regardless of its strategy. Testing strategy: replace is a
// read-time-only concern, so it gets its own instance with just the
// filters: role active.
async function runReplaceStrategyPhase(clients) {
  const port = 4885;
  const replaceWorkdir = fs.mkdtempSync(
    path.join(os.tmpdir(), 'security-filter-cli-replace-'),
  );
  const storageDir = path.join(replaceWorkdir, 'storage');
  const htpasswdFile = path.join(replaceWorkdir, 'htpasswd');
  const configFile = path.join(replaceWorkdir, 'config.yaml');

  const config = `
storage: ${storageDir}
plugins: ${PLUGINS_DIR}

auth:
  htpasswd:
    file: ${htpasswdFile}
    max_users: 1000

packages:
  '**':
    access: $authenticated
    publish: $authenticated

filters:
  '@fortmesa/verdaccio-security-filter':
    packageAge:
      minDays: 0
    block:
      - 'replace-test-*':
          versions: '2.0.0'
          strategy: replace

log:
  type: stdout
  format: pretty
  level: warn
`;
  fs.mkdirSync(path.dirname(htpasswdFile), {recursive: true});
  fs.writeFileSync(htpasswdFile, '');
  fs.mkdirSync(storageDir, {recursive: true});
  fs.writeFileSync(configFile, config);

  const proc = startVerdaccio(configFile, port);
  try {
    REGISTRY_URL = `http://127.0.0.1:${port}`;
    await waitForUp(`${REGISTRY_URL}/-/ping`);
    token = await registerUser('cli-real-replace-tester');

    for (const client of clients) {
      await check(
        `${client.name}: strategy: replace substitutes the blocked version's real content, not just remove`,
        () => {
          const slug = client.name.replace(/[^a-z0-9]+/gi, '-');
          const pkgName = `replace-test-${RUN_ID}-${slug}`;

          // v1.0.0 -- clean, becomes the substitute (not itself matched by
          // the versions: '2.0.0' rule).
          const v1Dir = makeProjectDir(pkgName, '1.0.0');
          client.setup(v1Dir);
          const publishV1 = client.publish(v1Dir);
          assert.equal(
            publishV1.status,
            0,
            `publishing v1.0.0 failed:\n${publishV1.stdout}\n${publishV1.stderr}`,
          );

          // v2.0.0 -- matches the block: rule, but strategy: replace means
          // the publish itself still succeeds (no blockPublishMatches here).
          const v2Dir = makeProjectDir(pkgName, '2.0.0');
          client.setup(v2Dir);
          const publishV2 = client.publish(v2Dir);
          assert.equal(
            publishV2.status,
            0,
            `publishing v2.0.0 failed:\n${publishV2.stdout}\n${publishV2.stderr}`,
          );

          // Installing "2.0.0" must succeed (replace never blocks installs)
          // and yield v1.0.0's REAL content -- the packument keeps the
          // 2.0.0 version key, but dist/tarball/integrity are copied
          // wholesale from the substitute.
          const installDir = makeProjectDir('consumer', '1.0.0', {
            [pkgName]: '2.0.0',
          });
          client.setup(installDir);
          const install = client.install(installDir);
          assert.equal(
            install.status,
            0,
            `install failed:\n${install.stdout}\n${install.stderr}`,
          );
          const installed = require(
            path.join(installDir, 'node_modules', pkgName, 'index.js'),
          );
          assert.equal(
            installed.marker,
            `${pkgName}@1.0.0`,
            "installing the blocked 2.0.0 must yield v1.0.0's real substitute content, not v2.0.0's own",
          );
        },
      );
    }
  } finally {
    proc.kill();
    fs.rmSync(replaceWorkdir, {recursive: true, force: true});
  }
}

// Real, non-empty audit coverage -- both advisories/bulk (npm 7+, yarn
// berry 4.x) and the older audits(/quick) protocol (npm 6, yarn berry
// 2.x/3.x), since every non-excluded client here ends up exercising
// whichever route its own real audit command actually calls. Seeds a
// genuine CVE-shaped record directly into the osv.filesystem backend's own
// on-disk format (one JSON file per item, named after the pk -- see
// filesystem-store.js) BEFORE starting verdaccio, so MaliciousPackageStore's
// own _warmStart() loads it at plugin construction time without ever
// attempting a real network sync against the real OSV feed. Also seeds a
// matching __sync_state__ item with the CURRENT extractionSchemaVersion and
// a truthy bootstrapCompletedAt -- otherwise _warmStart() would conclude no
// bootstrap has ever run and try one for real (see its own comment on
// compareSchemaVersion()).
async function runRealAdvisoryPhase(clients) {
  const port = 4886;
  const workdir = fs.mkdtempSync(
    path.join(os.tmpdir(), 'security-filter-cli-advisory-'),
  );
  const storageDir = path.join(workdir, 'storage');
  const htpasswdFile = path.join(workdir, 'htpasswd');
  const configFile = path.join(workdir, 'config.yaml');
  const osvDir = path.join(workdir, 'osv-data');

  // Same per-client pkgName convention every other phase in this file
  // uses (see e.g. the block: test above) -- a single shared pkgName
  // would mean only the first client in the loop can ever publish it;
  // every later client hits a 409 "already present" against the first
  // client's own publish.
  const targets = clients.filter(
    c => c.majorVersion !== '5' && !c.auditUnreachable,
  );
  const targetsByName = new Map(
    targets.map(client => {
      const slug = client.name.replace(/[^a-z0-9]+/gi, '-');
      return [
        client.name,
        {
          pkgName: `cli-real-advisory-${RUN_ID}-${slug}-pkg`,
          cveId: `GHSA-${RUN_ID}-${slug}-audit-test`,
        },
      ];
    }),
  );
  const {EXTRACTION_SCHEMA_VERSION} = require('../osv-client');

  fs.mkdirSync(osvDir, {recursive: true});
  fs.writeFileSync(
    path.join(osvDir, `${encodeURIComponent('__sync_state__')}.json`),
    JSON.stringify({
      pk: '__sync_state__',
      extractionSchemaVersion: EXTRACTION_SCHEMA_VERSION,
      bootstrapCompletedAt: new Date(0).toISOString(),
      lastSyncedModifiedId: null,
      csvEtag: null,
      csvLastModified: null,
    }),
  );
  for (const {pkgName, cveId} of targetsByName.values()) {
    fs.writeFileSync(
      path.join(osvDir, `${encodeURIComponent(pkgName)}.json`),
      JSON.stringify({
        pk: pkgName,
        modified: new Date(0).toISOString(),
        cves: [
          {
            id: cveId,
            cveId: null,
            severity: 'high',
            cweIds: ['CWE-1321'],
            cvss3Score: 7.5,
            cvss4Score: null,
            // Matches every version this phase publishes -- the point
            // here is proving the served advisory is real and correctly
            // shaped, not exercising vulnerableVersions' own range
            // precision (osv-client.js's unit tests already cover that
            // in depth).
            vulnerableVersions: '*',
          },
        ],
      }),
    );
  }

  const config = `
storage: ${storageDir}
plugins: ${PLUGINS_DIR}

auth:
  htpasswd:
    file: ${htpasswdFile}
    max_users: 1000

packages:
  '**':
    access: $authenticated
    publish: $authenticated

filters:
  '@fortmesa/verdaccio-security-filter':
    packageAge:
      minDays: 0
    osv:
      enabled: true
      filesystem:
        path: ${osvDir}

middlewares:
  '@fortmesa/verdaccio-security-filter': {}

log:
  type: stdout
  format: pretty
  level: warn
`;
  fs.mkdirSync(path.dirname(htpasswdFile), {recursive: true});
  fs.writeFileSync(htpasswdFile, '');
  fs.mkdirSync(storageDir, {recursive: true});
  fs.writeFileSync(configFile, config);

  const proc = startVerdaccio(configFile, port);
  try {
    REGISTRY_URL = `http://127.0.0.1:${port}`;
    await waitForUp(`${REGISTRY_URL}/-/ping`);
    token = await registerUser('cli-real-advisory-tester');

    for (const client of targets) {
      const {pkgName, cveId} = targetsByName.get(client.name);
      await check(
        `${client.name}: audit of a package WITH a real seeded advisory actually reports it`,
        () => {
          const pubDir = makeProjectDir(pkgName, '1.0.0');
          client.setup(pubDir);
          const publish = client.publish(pubDir);
          assert.equal(
            publish.status,
            0,
            `publish failed:\n${publish.stdout}\n${publish.stderr}`,
          );

          // Audit only reports on packages that are actually installed as
          // a dependency -- publishing pkgName doesn't put it in anyone's
          // own node_modules, so install/audit need a separate consumer
          // project that depends on it (same pattern as the block: test
          // above), not the publisher's own directory (which has no
          // dependencies at all, so npm's bulk payload would be empty and
          // it'd never even make the request).
          const installDir = makeProjectDir('consumer', '1.0.0', {
            [pkgName]: '1.0.0',
          });
          client.setup(installDir);
          const install = client.install(installDir);
          assert.equal(
            install.status,
            0,
            `install failed:\n${install.stdout}\n${install.stderr}`,
          );

          const audit = client.audit(installDir);
          const combined = audit.stdout + audit.stderr;
          if (!client.auditExitCodeUnreliable) {
            assert.notEqual(
              audit.status,
              0,
              `a real advisory was seeded for this exact package -- audit must exit non-zero:\n${combined}`,
            );
          }
          assert.match(
            combined,
            new RegExp(cveId),
            `the real seeded advisory's own id must actually appear in the audit output:\n${combined}`,
          );
        },
      );
    }
  } finally {
    proc.kill();
    fs.rmSync(workdir, {recursive: true, force: true});
  }
}

function installedVersion(dir, pkgName) {
  return JSON.parse(
    fs.readFileSync(
      path.join(dir, 'node_modules', pkgName, 'package.json'),
      'utf8',
    ),
  ).version;
}

// Confirms `npm audit fix` actually resolves a real vulnerability using
// nothing but the vulnerable_versions field this plugin serves via
// advisories/bulk -- npm's own @npmcli/metavuln-calculator Advisory class
// combines that range with the REAL registry's own version listing
// (fetched independently via pacote, nothing to do with this plugin) to
// pick a fix target; confirmed directly by reading its source (this.versions
// comes from the packument, this.range comes from vulnerable_versions), then
// confirmed again with a live publish/pin/fix round-trip by hand before
// writing this as a real automated test.
//
// npm 6 is included in the same loop, but with the OPPOSITE expectation:
// its own `npm audit fix` only ever acts on `actions` entries of type
// update/install, and legacy-audit.js only ever emits 'review' actions (see
// its own comment on why there's no reliable upgrade target to recommend)
// -- so npm 6's fix must be a safe, honest no-op here, not a crash and not
// a false claim of having fixed something it didn't.
//
// yarn has nothing to test here at all: `yarn npm audit` has no `fix`
// subcommand on ANY Berry major (confirmed directly against a real 4.17.0
// install's own `--help` output) -- Yarn deliberately never implemented
// automatic audit remediation, full stop. There's no gap in this plugin to
// close for that; the command a test could exercise simply doesn't exist.
async function runAuditFixPhase(clients) {
  const port = 4887;
  const workdir = fs.mkdtempSync(
    path.join(os.tmpdir(), 'security-filter-cli-auditfix-'),
  );
  const storageDir = path.join(workdir, 'storage');
  const htpasswdFile = path.join(workdir, 'htpasswd');
  const configFile = path.join(workdir, 'config.yaml');
  const osvDir = path.join(workdir, 'osv-data');
  const {EXTRACTION_SCHEMA_VERSION} = require('../osv-client');

  // Only npm clients have .installExact/.auditFix -- majorVersion is only
  // ever set by makeNpmClient(), and npm 5 predates `npm audit` (and so
  // `npm audit fix`) entirely.
  const npmClients = clients.filter(
    c => c.majorVersion && c.majorVersion !== '5',
  );

  fs.mkdirSync(osvDir, {recursive: true});
  fs.writeFileSync(
    path.join(osvDir, `${encodeURIComponent('__sync_state__')}.json`),
    JSON.stringify({
      pk: '__sync_state__',
      extractionSchemaVersion: EXTRACTION_SCHEMA_VERSION,
      bootstrapCompletedAt: new Date(0).toISOString(),
      lastSyncedModifiedId: null,
      csvEtag: null,
      csvLastModified: null,
    }),
  );

  const targetsByName = new Map(
    npmClients.map(client => {
      const slug = client.name.replace(/[^a-z0-9]+/gi, '-');
      return [
        client.name,
        {pkgName: `cli-real-auditfix-${RUN_ID}-${slug}-pkg`},
      ];
    }),
  );
  for (const {pkgName} of targetsByName.values()) {
    fs.writeFileSync(
      path.join(osvDir, `${encodeURIComponent(pkgName)}.json`),
      JSON.stringify({
        pk: pkgName,
        modified: new Date(0).toISOString(),
        cves: [
          {
            id: `GHSA-${RUN_ID}-auditfix-test`,
            cveId: null,
            severity: 'high',
            cweIds: [],
            cvss3Score: 7.5,
            cvss4Score: null,
            // Excludes 1.1.0 specifically -- both 1.0.0 and 1.1.0 get
            // published below, so a real fix target actually exists to
            // upgrade to, not just a hypothetical range with nothing on
            // the other side of it.
            vulnerableVersions: '<1.1.0',
          },
        ],
      }),
    );
  }

  const config = `
storage: ${storageDir}
plugins: ${PLUGINS_DIR}

auth:
  htpasswd:
    file: ${htpasswdFile}
    max_users: 1000

packages:
  '**':
    access: $authenticated
    publish: $authenticated

filters:
  '@fortmesa/verdaccio-security-filter':
    packageAge:
      minDays: 0
    osv:
      enabled: true
      filesystem:
        path: ${osvDir}

middlewares:
  '@fortmesa/verdaccio-security-filter': {}

log:
  type: stdout
  format: pretty
  level: warn
`;
  fs.mkdirSync(path.dirname(htpasswdFile), {recursive: true});
  fs.writeFileSync(htpasswdFile, '');
  fs.mkdirSync(storageDir, {recursive: true});
  fs.writeFileSync(configFile, config);

  const proc = startVerdaccio(configFile, port);
  try {
    REGISTRY_URL = `http://127.0.0.1:${port}`;
    await waitForUp(`${REGISTRY_URL}/-/ping`);
    token = await registerUser('cli-real-auditfix-tester');

    for (const client of npmClients) {
      const {pkgName} = targetsByName.get(client.name);
      const label = client.usesLegacyAudit
        ? 'npm audit fix is a safe no-op (no auto-fix target this plugin can honestly recommend over the legacy protocol)'
        : 'npm audit fix actually upgrades away from the vulnerable version';
      await check(`${client.name}: ${label}`, () => {
        const v1Dir = makeProjectDir(pkgName, '1.0.0');
        client.setup(v1Dir);
        const publishV1 = client.publish(v1Dir);
        assert.equal(
          publishV1.status,
          0,
          `publish 1.0.0 failed:\n${publishV1.stdout}\n${publishV1.stderr}`,
        );

        const v2Dir = makeProjectDir(pkgName, '1.1.0');
        client.setup(v2Dir);
        const publishV2 = client.publish(v2Dir);
        assert.equal(
          publishV2.status,
          0,
          `publish 1.1.0 failed:\n${publishV2.stdout}\n${publishV2.stderr}`,
        );

        // Declares a range wide enough to permit the fixed 1.1.0 (^1.0.0),
        // but installExact pins what's actually resolved/on-disk to the
        // vulnerable 1.0.0 -- exactly the "an in-range fix is available,
        // just not yet applied" situation `npm audit fix` exists for.
        const consumerDir = makeProjectDir('consumer', '1.0.0', {
          [pkgName]: '^1.0.0',
        });
        client.setup(consumerDir);
        const install = client.installExact(consumerDir, `${pkgName}@1.0.0`);
        assert.equal(
          install.status,
          0,
          `pinned install of 1.0.0 failed:\n${install.stdout}\n${install.stderr}`,
        );
        assert.equal(
          installedVersion(consumerDir, pkgName),
          '1.0.0',
          'setup invariant: must actually start on the vulnerable version before fixing it',
        );

        const fix = client.auditFix(consumerDir);
        assert.equal(
          fix.status,
          0,
          `npm audit fix crashed:\n${fix.stdout}\n${fix.stderr}`,
        );

        const finalVersion = installedVersion(consumerDir, pkgName);
        if (client.usesLegacyAudit) {
          assert.equal(
            finalVersion,
            '1.0.0',
            `npm audit fix must NOT silently change anything here -- this plugin never recommends an automatic upgrade target over the legacy protocol, so the version must stay put:\n${fix.stdout}\n${fix.stderr}`,
          );
        } else {
          assert.equal(
            finalVersion,
            '1.1.0',
            `npm audit fix should have upgraded off the vulnerable version using only the vulnerable_versions range served by advisories/bulk:\n${fix.stdout}\n${fix.stderr}`,
          );
        }
      });
    }
  } finally {
    proc.kill();
    fs.rmSync(workdir, {recursive: true, force: true});
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
