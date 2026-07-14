'use strict';

const semver = require('semver');
// Pinned to 1.x deliberately -- DO NOT bump to 2.x. Verdaccio's own core
// publish handler still bundles body-parser@1.20.5 internally, and 1.x/2.x
// don't safely chain: 1.x's read() flags an already-consumed request via an
// explicit req._body flag set synchronously; 2.x instead checks
// onFinished.isFinished(req), an async/event-based signal that can still
// read false immediately after a *different* body-parser instance already
// fully drained the stream. Confirmed by direct repro (chaining this
// plugin's own bodyParser.json() ahead of Verdaccio's bundled 1.x instance
// on one real request): 1-then-1 and 2-then-2 both work, but 2-then-1 fails
// every time with "stream is not readable" -- silently breaking every
// publish once this middleware's own parser has already run (see also
// verdaccio-attestations' own middleware, which shares this exact
// constraint). Only safe to upgrade this once Verdaccio's own bundled
// body-parser also moves to 2.x.
const bodyParser = require('body-parser');
const {minimatch} = require('minimatch');
const {getAdvisoryStore} = require('./malicious-packages');
const {sendWebhook} = require('./webhook');
const {cveToNpmAdvisory, buildLegacyAuditReport} = require('./legacy-audit');
const {
  DEFAULT_SENSITIVE_PATHS,
  findDirectSensitivePathTouch,
  extractReferencedScriptFiles,
  findIndirectSensitivePathTouch,
  extractTarballFiles,
} = require('./sensitive-paths');

// Must match this package's name: Verdaccio's plugin loader resolves a
// scoped package name verbatim as the config key (no `verdaccio-` prefix
// mangling), and both the `filters:` and `middlewares:` sections need to
// agree on this key for the shared-config lookup below to find each other.
const PLUGIN_CONFIG_KEY = '@fortmesa/verdaccio-security-filter';

// Scripts that execute when a package is installed as a registry dependency.
// prepare/prepack/postpack only run locally or during publish, not on npm install.
const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall'];

function hasInstallScript(versionMeta) {
  return INSTALL_SCRIPTS.some(s => s in (versionMeta?.scripts ?? {}));
}

// The existing "newly introduced" check above only ever compares script
// *presence* (a key appearing that wasn't there before) -- a compromise that
// modifies an *existing* install script's own command string (common for a
// package that's always legitimately shipped one, e.g. for a native build)
// would never trip it at all, since the key was already present in both the
// old and new version. This compares content directly: any INSTALL_SCRIPTS
// key present in both versions, with a different command string, is exactly
// as suspicious as a newly-added one -- same threat category, same
// treatment. Deliberately not gated by scriptIntroductionIsRecent (see
// filter_metadata()'s own use of that flag) -- that flag answers "when did
// this package first start shipping scripts at all", a different, unrelated
// question from "did this specific version change an existing script's
// content", which is inherently about the version just published, not
// history.
function changedInstallScripts(previousVersionMeta, currentVersionMeta) {
  const previousScripts = previousVersionMeta?.scripts ?? {};
  const currentScripts = currentVersionMeta?.scripts ?? {};
  return INSTALL_SCRIPTS.filter(
    s =>
      s in previousScripts &&
      s in currentScripts &&
      previousScripts[s] !== currentScripts[s],
  );
}

// Structural obfuscation heuristics for lifecycle script command strings --
// deliberately not literal known-bad string/IOC matching, since real
// malicious payloads are near-universally obfuscated specifically to evade
// that. Scoped to the scripts field's own command text only (not tarball
// contents -- unpacking every tarball to scan referenced files is a much
// bigger scope increase than this plugin takes on).
//
// Ranked by how much a hit alone actually means:
// - shellPipe: piping a fetched payload straight into a shell interpreter.
//   High confidence, low false-positive rate -- legitimate installers don't
//   need to do this even when they do fetch something (they'd write a file
//   and let node execute it, not exec a downloaded script blind).
// - evalOrFunction: `eval(...)`/`new Function(...)` in the command string.
// - longBase64Blob: a long contiguous base64-alphabet run, the shape of an
//   inlined obfuscated/encoded payload.
// - networkCall: curl/wget/a raw IP-shaped URL. Real, common, LEGITIMATE
//   lifecycle scripts do this too (node-gyp, sharp, esbuild all fetch
//   prebuilt binaries this way) -- this alone means nothing; it only adds
//   confidence alongside another signal.
const SHELL_PIPE_PATTERN = /\b(curl|wget)\b[^|;\n]*\|\s*(sh|bash|zsh|node)\b/i;
const EVAL_PATTERN = /\b(eval|new\s+Function)\s*\(/;
// Deliberately excludes "/" from the alphabet, unlike standard base64 --
// real-world URLs (github.com/foo/bar/releases/download/...) are otherwise
// indistinguishable from a base64 run under a naive character-class check,
// confirmed directly: a real prebuilt-binary download URL matched this
// exact pattern before "/" was excluded. This only loses detection of
// standard (not URL-safe) base64 strings that happen to need a "/" byte in
// this exact 40-char window -- a narrow miss, far better than flagging
// ordinary URLs as "a base64 blob" and defeating the bare-network-call
// carve-out below.
const LONG_BASE64_PATTERN =
  /(?:[A-Za-z0-9+]{4}){10,}(?:[A-Za-z0-9+]{2}==|[A-Za-z0-9+]{3}=)?/;
const NETWORK_CALL_PATTERN =
  /\b(curl|wget)\b|https?:\/\/(?:\d{1,3}\.){3}\d{1,3}\b/i;

// Returns null if nothing rises above "too common in legitimate scripts to
// mean anything alone" -- specifically, a bare network call with no other
// signal alongside it.
function classifySuspiciousScript(command) {
  if (typeof command !== 'string' || command.length === 0) return null;
  const hits = [];
  if (SHELL_PIPE_PATTERN.test(command)) hits.push('shell-pipe');
  if (EVAL_PATTERN.test(command)) hits.push('eval');
  if (LONG_BASE64_PATTERN.test(command)) hits.push('base64-blob');
  if (NETWORK_CALL_PATTERN.test(command)) hits.push('network-call');
  if (hits.length === 0) return null;
  if (hits.length === 1 && hits[0] === 'network-call') return null;
  return {hits, highConfidence: hits.includes('shell-pipe')};
}

// Checks every INSTALL_SCRIPTS command in a version's own scripts field --
// returns the first classified hit found, alongside which script key it
// came from, or null. One hit is enough to act on; this isn't trying to
// enumerate every offending script in a version, just to catch one.
function findSuspiciousScript(versionMeta) {
  const scripts = versionMeta?.scripts ?? {};
  for (const key of INSTALL_SCRIPTS) {
    if (!(key in scripts)) continue;
    const classified = classifySuspiciousScript(scripts[key]);
    if (classified) return {key, command: scripts[key], ...classified};
  }
  return null;
}

// Same shape/style as findSuspiciousScript() above, for the sensitive-path
// touch check -- see sensitive-paths.js for the actual pattern matching.
// `tarballFiles` (Map<relativePath, content>) is only ever populated at
// publish time (see _checkPublish()'s own tarball extraction below);
// filter_metadata() has no tarball to inspect, so it always passes null here,
// which naturally limits it to the direct, command-text-only check.
function findSensitivePathTouch(versionMeta, tarballFiles, paths) {
  const scripts = versionMeta?.scripts ?? {};
  for (const key of INSTALL_SCRIPTS) {
    const command = scripts[key];
    if (!command) continue;
    const direct = findDirectSensitivePathTouch(command, paths);
    if (direct) return {key, command, type: 'direct', matched: direct};
    const indirect = findIndirectSensitivePathTouch(
      command,
      tarballFiles,
      paths,
    );
    if (indirect)
      return {
        key,
        command,
        type: 'indirect',
        matched: indirect.matched,
        file: indirect.file,
      };
  }
  return null;
}

// `paths` must be a non-empty-string array -- validated unconditionally (even
// when sensitivePaths.enabled is false), matching every other config
// validator in this file: a typo here should fail loud at startup, not
// silently do nothing once an operator later flips enabled: true.
function parseSensitivePaths(list) {
  if (
    !Array.isArray(list) ||
    list.length === 0 ||
    list.some(p => typeof p !== 'string' || p.length === 0)
  ) {
    throw new Error(
      'security-filter: sensitivePaths.paths must be a non-empty array of non-empty strings',
    );
  }
  return list;
}

// The publish request's own `_attachments` map keys the tarball by
// `${packageName}-${version}.tgz` (confirmed directly against npm's own
// publish payload construction, libnpmpublish's publish.js) -- tries every
// version this request is actually adding, since in principle more than one
// could be, though in practice npm/yarn only ever send one per publish.
function getAttachmentBuffer(body, packageName, versions) {
  const attachments = body?._attachments;
  if (!attachments || typeof attachments !== 'object') return null;
  for (const ver of versions) {
    const attachment = attachments[`${packageName}-${ver}.tgz`];
    if (attachment?.data) return Buffer.from(attachment.data, 'base64');
  }
  return null;
}

// True if at least one already-stored version of the package has no install
// script -- i.e. there's an established "clean" baseline a new script could
// be violating. A package that has *always* shipped install scripts (e.g. a
// native addon) has no such baseline, so this rule never applies to it.
function hasCleanBaseline(existingVersions) {
  return Object.values(existingVersions).some(v => !hasInstallScript(v));
}

// Manual block:/allow: rule matching. Each entry is either a bare glob
// pattern string (matches every version) or a single-key {pattern: {versions?,
// strategy?}} object for version-scoped/replace rules -- same bare-string-or-
// single-key-object shape osv.cve.cwe below already uses. Patterns use real
// minimatch -- the same convention Verdaccio's own packages: access-control
// config uses (@verdaccio/utils's getMatchedPackagesSpec), not a narrower
// hand-rolled matcher -- so an operator configuring this plugin already
// knows this syntax from Verdaccio core itself, and every plugin in this
// family (see verdaccio-attestations) matches package names the same way.
function matchesPackage(rule, name) {
  return minimatch(name, rule.pattern);
}
function matchesVersion(rule, version) {
  return (
    !rule.versions ||
    semver.satisfies(version, rule.versions, {includePrerelease: true})
  );
}
function findMatchingRules(rules, name, version) {
  return rules.filter(
    r => matchesPackage(r, name) && matchesVersion(r, version),
  );
}
function describeRule(rule) {
  return rule.versions ? `${rule.pattern}@${rule.versions}` : rule.pattern;
}

function normalizeRule(entry, source) {
  if (typeof entry === 'string') return {pattern: entry};
  if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
    const keys = Object.keys(entry);
    if (keys.length !== 1) {
      throw new Error(
        `security-filter: ${source} rule must have exactly one pattern key: ${JSON.stringify(entry)}`,
      );
    }
    const [pattern] = keys;
    const details = entry[pattern] ?? {};
    if (typeof details !== 'object' || Array.isArray(details)) {
      throw new Error(
        `security-filter: ${source} rule for '${pattern}' must map to an object with optional 'versions'/'strategy'`,
      );
    }
    return {pattern, versions: details.versions, strategy: details.strategy};
  }
  throw new Error(
    `security-filter: ${source} rule must be a pattern string or {pattern: {versions?, strategy?}} object: ${JSON.stringify(entry)}`,
  );
}

// Fail loud at startup on a malformed rule, not silently-matches-nothing (or
// matches-everything) at request time -- this is a security control.
function compileRules(rules, source) {
  return rules.map(entry => {
    const rule = normalizeRule(entry, source);
    if (rule.versions && !semver.validRange(rule.versions)) {
      throw new Error(
        `security-filter: ${source} rule has invalid semver range '${rule.versions}': ${JSON.stringify(entry)}`,
      );
    }
    if (
      rule.strategy &&
      rule.strategy !== 'remove' &&
      rule.strategy !== 'replace'
    ) {
      throw new Error(
        `security-filter: ${source} rule has invalid strategy '${rule.strategy}' (must be 'remove' or 'replace')`,
      );
    }
    return rule;
  });
}

// Nearest older non-blocked version, falling back to nearest newer, then
// null (caller hard-removes) if nothing is available at all. `available` is
// pre-sorted ascending by semver.
function pickReplacementSubstitute(ver, available) {
  const older = available.filter(v => semver.lt(v, ver));
  if (older.length > 0) return older[older.length - 1];
  const newer = available.filter(v => semver.gt(v, ver));
  if (newer.length > 0) return newer[0];
  return null;
}

class SecurityFilter {
  constructor(config, options) {
    this.logger = options.logger;
    const packageAge = config.packageAge ?? {};
    this.minAgeDays = packageAge.minDays ?? 2;
    this.minAgeMs = this.minAgeDays * 24 * 60 * 60 * 1000;
    this.scriptCheckDays = packageAge.scriptCheckDays ?? 30;
    this.scriptCheckMs = this.scriptCheckDays * 24 * 60 * 60 * 1000;

    // Only serve versions published before this date -- combined with
    // minDays via "earlier cutoff wins" in filter_metadata(), matching
    // @verdaccio/package-filter's documented semantics. Accepts either a
    // bare date ("2026-01-01") or a full ISO-8601 timestamp -- Date.parse()
    // natively handles both.
    if (
      packageAge.thresholdDate != null &&
      Number.isNaN(Date.parse(packageAge.thresholdDate))
    ) {
      throw new Error(
        `security-filter: invalid packageAge.thresholdDate '${packageAge.thresholdDate}'`,
      );
    }
    this.dateThresholdMs =
      packageAge.thresholdDate != null
        ? Date.parse(packageAge.thresholdDate)
        : null;

    // Manual block:/allow: lists. filters: "@fortmesa/verdaccio-security-filter":
    // and middlewares: "@fortmesa/verdaccio-security-filter": are two
    // independent plugin instances (Verdaccio's loader instantiates each
    // config-section entry separately) -- read from the canonical filters:
    // section of the *full* app config (the same pattern max_body_size below
    // already uses) so both instances agree on one rule set without
    // operators needing to duplicate block/allow under both sections. Falls
    // back to this instance's own config for the test harness, which passes
    // a bare `config: {}` as options.config. Must be the literal, scoped
    // package name -- Verdaccio's config key for a scoped plugin is never
    // prefix-mangled, so a bare 'security-filter' here would never match a
    // real deployment's actual filters: key and always silently fall
    // through to `?? config` instead.
    const sharedConfig = options.config?.filters?.[PLUGIN_CONFIG_KEY] ?? config;
    this.blockRules = compileRules(sharedConfig.block ?? [], 'block');
    this.allowRules = compileRules(sharedConfig.allow ?? [], 'allow');

    // Single, static, operator-configured webhook target -- fired for every
    // "loud" security event (publish-time gate rejections, and OSV sync
    // discovering an already-cached package now matches new MAL/CVE data).
    // See docs/configuration.md's "Webhooks" section and webhook.js.
    this.webhookConfig = sharedConfig.webhook ?? null;
    if (this.webhookConfig && !this.webhookConfig.url) {
      throw new Error('security-filter: webhook is configured but has no url');
    }

    // OSV malicious-package blocklist -- see malicious-packages.js. The
    // store is a singleton shared by both plugin instances in this
    // process; getAdvisoryStore() is an inert no-op factory unless
    // osv.enabled is set. options.maliciousPackageStore lets tests inject
    // a fake store without touching the real singleton. webhookConfig is
    // threaded through so the sync loop's own retroactive-match check (see
    // malicious-packages.js) can fire the same webhook this instance would.
    this.osvBlockStrategy = config.osv?.blockStrategy ?? 'remove';
    this.maliciousPackageStore =
      options.maliciousPackageStore ??
      getAdvisoryStore(sharedConfig.osv ?? {}, {
        ...options,
        webhookConfig: this.webhookConfig,
      });

    // Publish-time gates -- see register_middlewares() below. Only active
    // when this plugin is also listed under `middlewares:` in config.yaml;
    // the `filters:`-only role above is unaffected either way.
    this.blockPublishWithNewScripts =
      config.blockPublishWithNewScripts ?? false;
    this.blockPublishMatches = config.blockPublishMatches ?? false;

    // Structural obfuscation heuristics -- see classifySuspiciousScript()'s
    // own comment for the full rationale and confidence ranking. Opt-in,
    // matching every other feature area in this plugin (osv.enabled,
    // blockPublishWithNewScripts, ...) rather than auto-enabling new
    // pattern-matching behavior. Read-only (alert via webhook, never
    // block/reject) by default even when enabled -- blockShellPipe is a
    // second, separate opt-in specifically for the one pattern confident
    // enough to justify actually blocking on.
    const scriptHeuristics = sharedConfig.scriptHeuristics ?? {};
    this.scriptHeuristicsEnabled = scriptHeuristics.enabled ?? false;
    this.blockShellPipe = scriptHeuristics.blockShellPipe ?? false;

    // Sensitive-path touch -- an install script (directly, in its own command
    // text, or indirectly, via a bundled file it invokes) referencing a
    // credential/config/auto-run path it has no legitimate reason to touch.
    // See sensitive-paths.js and docs/configuration.md's "Sensitive path
    // touch" section. Same opt-in/second-gate shape as scriptHeuristics
    // above: `enabled` alone only alerts (webhook + log); `block` also
    // rejects the publish / hides the version, same as blockShellPipe does
    // for the obfuscation heuristics.
    const sensitivePathsConfig = sharedConfig.sensitivePaths ?? {};
    this.sensitivePathsEnabled = sensitivePathsConfig.enabled ?? false;
    this.blockSensitivePathTouch = sensitivePathsConfig.block ?? false;
    this.sensitivePaths = parseSensitivePaths(
      sensitivePathsConfig.paths ?? DEFAULT_SENSITIVE_PATHS,
    );

    // Matches Verdaccio's own global JSON body limit (api/endpoint/index.js
    // uses the same `max_body_size || '10mb'` fallback) so this gate never
    // diverges from what Verdaccio itself would accept as a request size.
    this._parseJsonBody = bodyParser.json({
      strict: false,
      limit: options.config?.max_body_size || '10mb',
    });
  }

  async filter_metadata(packageInfo) {
    const versions = packageInfo.versions ?? {};
    const time = packageInfo.time ?? {};
    const now = Date.now();

    // Sort versions oldest-first so we can track install-script history chronologically
    const sortedByAge = Object.keys(versions).sort(
      (a, b) => new Date(time[a] ?? 0) - new Date(time[b] ?? 0),
    );

    // "Earlier cutoff wins" -- whichever bound is chronologically earlier
    // blocks more (it draws the line further back in time), matching
    // @verdaccio/package-filter's documented minAgeDays/dateThreshold
    // interaction.
    const ageCutoffMs = now - this.minAgeMs;
    const effectiveCutoffMs =
      this.dateThresholdMs != null
        ? Math.min(ageCutoffMs, this.dateThresholdMs)
        : ageCutoffMs;
    const cutoffKind =
      this.dateThresholdMs != null && this.dateThresholdMs <= ageCutoffMs
        ? 'dateThreshold'
        : 'minAgeDays';

    // Pre-pass: find when install scripts were first introduced after a clean version.
    // If that transition happened long ago it is established behaviour, not an attack.
    let seenClean = false;
    let scriptIntroductionAge = Infinity;
    for (const ver of sortedByAge) {
      const publishedAt = time[ver] ? new Date(time[ver]).getTime() : null;
      const isScripted = hasInstallScript(versions[ver]);
      if (isScripted && seenClean && publishedAt !== null) {
        scriptIntroductionAge = now - publishedAt;
        break;
      }
      if (!isScripted) seenClean = true;
    }
    const scriptIntroductionIsRecent =
      scriptIntroductionAge < this.scriptCheckMs;

    const blocked = new Set();
    const replaceRequested = new Set();
    let seenCleanVersion = false;
    // Tracks the immediately-preceding version's own metadata (in the same
    // oldest-first order as everything else here), regardless of whether
    // that version itself ended up blocked -- content-diffing needs the
    // actual publish history, not just the versions that passed every other
    // check. Updated in the finally block below so every continue path
    // still advances it.
    let previousVersionMeta = null;

    for (const ver of sortedByAge) {
      try {
        const publishedAt = time[ver] ? new Date(time[ver]).getTime() : null;

        // 1. Allow-list -- bypasses everything below, including the OSV check.
        if (
          findMatchingRules(this.allowRules, packageInfo.name, ver).length > 0
        ) {
          if (!hasInstallScript(versions[ver])) seenCleanVersion = true;
          continue;
        }

        // 2. OSV synced malicious-package/CVE blocklist.
        const osvHit = this.maliciousPackageStore?.check(packageInfo.name, ver);
        if (osvHit) {
          blocked.add(ver);
          if (this.osvBlockStrategy === 'replace') replaceRequested.add(ver);
          if (osvHit.type === 'cve') {
            this.logger.warn(
              {
                pkg: packageInfo.name,
                ver,
                cveId: osvHit.cveId,
                severity: osvHit.severity,
                cweIds: osvHit.cweIds,
              },
              'security-filter: blocked -- version matches known vulnerability @{cveId} [@{severity}, @{cweIds}] (OSV)',
            );
          } else {
            this.logger.warn(
              {pkg: packageInfo.name, ver, malIds: osvHit.malIds},
              'security-filter: blocked -- version matches known-malicious-package advisory [@{malIds}] (OSV)',
            );
          }
          continue;
        }

        // 3. Manual block: list.
        const matchedBlockRules = findMatchingRules(
          this.blockRules,
          packageInfo.name,
          ver,
        );
        if (matchedBlockRules.length > 0) {
          blocked.add(ver);
          const strategy = matchedBlockRules.every(
            r => r.strategy === 'replace',
          )
            ? 'replace'
            : 'remove';
          if (strategy === 'replace') replaceRequested.add(ver);
          this.logger.warn(
            {
              pkg: packageInfo.name,
              ver,
              rule: matchedBlockRules.map(describeRule).join(', '),
            },
            `security-filter: blocked -- matched manual block list${strategy === 'replace' ? ' (replace)' : ''}`,
          );
          continue;
        }

        // 4. Age / date, combined.
        if (publishedAt === null) {
          blocked.add(ver);
          this.logger.warn(
            {pkg: packageInfo.name, ver},
            'security-filter: blocked -- publish date unknown',
          );
          continue;
        }
        if (publishedAt >= effectiveCutoffMs) {
          blocked.add(ver);
          this.logger.warn(
            {pkg: packageInfo.name, ver, cutoff: cutoffKind},
            'security-filter: blocked -- version too new',
          );
          continue;
        }

        // 5. Install-script introduction -- existing, unchanged.
        const installScriptKeys = INSTALL_SCRIPTS.filter(
          s => s in (versions[ver].scripts ?? {}),
        );
        const isScripted = installScriptKeys.length > 0;

        // Block if this package recently introduced install scripts after previously having none.
        // scriptIntroductionIsRecent ensures packages like esbuild (scripts added years ago) are never blocked.
        if (isScripted && seenCleanVersion && scriptIntroductionIsRecent) {
          blocked.add(ver);
          this.logger.error(
            {pkg: packageInfo.name, ver, scripts: installScriptKeys},
            'security-filter: blocked -- install scripts newly introduced in this version',
          );
          continue;
        }

        // 5b. Install-script content changed -- see changedInstallScripts()'s
        // own comment for why this is a distinct check from the
        // presence-only one above.
        const changedScripts = changedInstallScripts(
          previousVersionMeta,
          versions[ver],
        );
        if (changedScripts.length > 0) {
          blocked.add(ver);
          this.logger.error(
            {pkg: packageInfo.name, ver, scripts: changedScripts},
            'security-filter: blocked -- install script content changed from the previous version',
          );
          continue;
        }

        // 5c. Structural obfuscation heuristics -- see
        // classifySuspiciousScript()'s own comment for the confidence
        // ranking. Deliberately no webhook here, unlike the publish-time
        // gate's own version of this check below -- filter_metadata() runs on
        // every metadata read of a gated package, potentially far more often
        // than it's actually published, and every other read-time check in
        // this method already only logs, never alerts, for the same reason.
        if (this.scriptHeuristicsEnabled) {
          const suspicious = findSuspiciousScript(versions[ver]);
          if (suspicious) {
            if (suspicious.highConfidence && this.blockShellPipe) {
              blocked.add(ver);
              this.logger.error(
                {
                  pkg: packageInfo.name,
                  ver,
                  script: suspicious.key,
                  hits: suspicious.hits,
                },
                'security-filter: blocked -- install script matches a high-confidence obfuscation/exfiltration pattern (@{hits})',
              );
              continue;
            }
            this.logger.warn(
              {
                pkg: packageInfo.name,
                ver,
                script: suspicious.key,
                hits: suspicious.hits,
              },
              'security-filter: install script matches a suspicious pattern (@{hits}), not blocked',
            );
          }
        }

        // 5d. Sensitive-path touch -- direct check only. There's no tarball
        // to inspect at read time (only _checkPublish() ever sees the raw
        // publish attachment), so the indirect, invoked-file check never
        // fires here -- see findSensitivePathTouch()'s own comment. Same
        // "log only, no webhook" posture as 5c above, for the same reason.
        if (this.sensitivePathsEnabled) {
          const hit = findSensitivePathTouch(
            versions[ver],
            null,
            this.sensitivePaths,
          );
          if (hit) {
            if (this.blockSensitivePathTouch) {
              blocked.add(ver);
              this.logger.error(
                {
                  pkg: packageInfo.name,
                  ver,
                  script: hit.key,
                  matched: hit.matched,
                },
                'security-filter: blocked -- install script references sensitive path @{matched}',
              );
              continue;
            }
            this.logger.warn(
              {
                pkg: packageInfo.name,
                ver,
                script: hit.key,
                matched: hit.matched,
              },
              'security-filter: install script references sensitive path @{matched}, not blocked',
            );
          }
        }

        if (!isScripted) {
          seenCleanVersion = true;
        }
      } finally {
        previousVersionMeta = versions[ver];
      }
    }

    if (blocked.size === 0) return packageInfo;

    // Computed before the delete/replace loop below -- deliberately
    // excludes anything in `blocked`, including versions about to be
    // replaced, so a substitute or a dist-tag redirect never points at an
    // already-aliased version.
    const available = sortedByAge
      .filter(v => !blocked.has(v))
      .sort((a, b) => semver.compare(a, b));
    const availableStable = available.filter(
      v => semver.prerelease(v) === null,
    );

    for (const ver of blocked) {
      if (replaceRequested.has(ver)) {
        const substitute = pickReplacementSubstitute(ver, available);
        if (substitute) {
          // Copies the substitute's *entire* metadata (including dist/tarball/
          // integrity) as one consistent unit, so the tarball a client
          // downloads for `ver` is the substitute's real, already-published one.
          packageInfo.versions[ver] = {
            ...packageInfo.versions[substitute],
            version: ver,
          };
          this.logger.warn(
            {pkg: packageInfo.name, ver, substitutedWith: substitute},
            'security-filter: blocked -- replaced with nearest available version',
          );
          continue; // keep the key -- do not delete
        }
        this.logger.warn(
          {pkg: packageInfo.name, ver},
          'security-filter: blocked -- replace requested but no substitute version available, removed instead',
        );
      }
      delete packageInfo.versions[ver];
      delete packageInfo.time[ver];
    }

    // Redirect dist-tags that pointed at a version actually removed above --
    // a replaced version keeps its key, so no redirect is needed for it.
    const distTags = packageInfo['dist-tags'] ?? {};
    for (const tag of Object.keys(distTags)) {
      if (distTags[tag] in packageInfo.versions) continue;
      // Prefer stable versions as redirect targets; fall back to pre-release if nothing else available
      const candidates =
        availableStable.length > 0 ? availableStable : available;
      if (candidates.length > 0) {
        const latest = candidates[candidates.length - 1];
        this.logger.warn(
          {pkg: packageInfo.name, tag, was: distTags[tag], now: latest},
          'security-filter: dist-tag redirected away from blocked version',
        );
        distTags[tag] = latest;
      } else {
        delete distTags[tag];
      }
    }

    return packageInfo;
  }

  // This whole method only ever runs if this plugin is ALSO listed under
  // `middlewares:` in config.yaml (Verdaccio only constructs a plugin's
  // middleware-role instance, and so only ever calls this hook, for config
  // sections that reference it there) -- the `filters:` role above is a
  // separate instance, independent and unaffected either way. That's now
  // true even for an operator who wants NOTHING but the advisories/bulk
  // endpoint below: an empty `middlewares: {'@fortmesa/verdaccio-security-
  // filter': {}}` section is enough to get it registered, no publish-gate
  // flag required.
  //
  // Publish-time gates: REJECT (not just hide) a publish that either
  // introduces a preinstall/install/postinstall script not present in any
  // version this registry already has stored for that package
  // (blockPublishWithNewScripts), matches the OSV malicious-package
  // blocklist or a manual block: rule (blockPublishMatches), or (with
  // sensitivePaths.enabled) touches a credential/config/auto-run path --
  // whether the target is an internal @fortmesa/* package or one that also
  // proxies reads to npmjs via '**'; all three run on the publish path
  // itself, before storage, so they apply identically regardless of which
  // `packages:` pattern the name matches. Gated below on at least one of the
  // three being true -- unlike advisories/bulk above, these have real
  // side effects an operator must opt into explicitly.
  register_middlewares(app, auth, storage) {
    // Unconditional, regardless of the two flags below: this is the only
    // Verdaccio hook that ever receives a `storage` reference, and the OSV
    // singleton's own retroactive-match check (see malicious-packages.js's
    // _checkAgainstLocalStorage()) needs it independently of whether the
    // publish-time reject gates are also enabled here.
    this.maliciousPackageStore?.attachRegistryStorage?.(storage);

    // Real npm/yarn `npm audit`/`yarn npm audit` protocol endpoint --
    // registered unconditionally, regardless of the two publish-gate flags
    // below or of osv.enabled (an unconfigured/disabled OSV store just
    // means every lookup below comes back empty, same honest `{}` result
    // as before real data existed). Confirmed directly why this route has
    // to exist at all, valid response or not: npm's own `npm audit`
    // degrades gracefully on a 404 (a clean, informative error, exit code
    // 1), but yarn berry 4.x's `yarn npm audit` throws an uncaught
    // exception and dumps a raw stack trace instead of failing gracefully.
    //
    // Unfiltered by this deployment's own osv.cve.* block-policy
    // thresholds -- see getCveAdvisories()'s own comment for why. MAL
    // (malicious-package) data is deliberately NOT included yet -- see
    // docs/configuration.md's "Audit / advisory endpoints" section.
    app.use((req, res, next) => {
      if (
        req.method !== 'POST' ||
        req.path !== '/-/npm/v1/security/advisories/bulk'
      ) {
        return next();
      }
      this._parseJsonBody(req, res, err => {
        if (err) return next(err);
        const requested =
          req.body && typeof req.body === 'object' ? req.body : {};
        const result = {};
        for (const packageName of Object.keys(requested)) {
          // Real advisories/bulk requests send {name: [version, ...]} --
          // the client's own actually-installed version(s), not a range.
          // Skipping when this isn't a non-empty array (rather than passing
          // it through and letting getCveAdvisories() throw) keeps a
          // malformed/empty entry a silent no-op here, matching this
          // route's overall honest-empty-result posture for anything it
          // can't make sense of, same as legacy-audit.js's own handling of
          // a malformed body.
          const versions = Array.isArray(requested[packageName])
            ? requested[packageName]
            : [];
          if (versions.length === 0) continue;
          const cves =
            this.maliciousPackageStore?.getCveAdvisories(
              packageName,
              versions,
            ) ?? [];
          if (cves.length === 0) continue;
          result[packageName] = cves.map(cve =>
            cveToNpmAdvisory(packageName, cve),
          );
        }
        res.status(200).json(result);
      });
    });

    // Older /-/npm/v1/security/audits(/quick) protocol -- npm 6 and below
    // have no concept of advisories/bulk at all (confirmed directly against
    // npm 6's own lib/audit.js and lib/install/audit.js), and yarn 2.x/3.x's
    // own `yarn npm audit` always calls /quick too (confirmed directly
    // against real 2.4.3/3.8.7 bundles -- yarn 4.x is the only Berry major
    // that actually uses advisories/bulk). Unlike bulk, the client submits
    // its own full dependency tree/graph here rather than a flat {name:
    // [versions]} map, so the real work is walking that tree -- see
    // legacy-audit.js for how, and for why every remediation action is
    // 'review' rather than an automatic 'update'/'install' recommendation.
    // Same unconditional/unfiltered/no-MAL-yet posture as advisories/bulk
    // above.
    //
    // yarn classic (1.x) is NOT covered by this route despite also calling
    // an /audits endpoint -- confirmed directly (`yarn audit --verbose`)
    // that it hardcodes its request to the real
    // https://registry.yarnpkg.com/-/npm/v1/security/audits, ignoring
    // whatever registry is actually configured. No route this plugin can
    // register will ever be reached by it.
    app.use((req, res, next) => {
      if (
        req.method !== 'POST' ||
        (req.path !== '/-/npm/v1/security/audits' &&
          req.path !== '/-/npm/v1/security/audits/quick')
      ) {
        return next();
      }
      this._parseJsonBody(req, res, err => {
        if (err) return next(err);
        const body = req.body && typeof req.body === 'object' ? req.body : {};
        res
          .status(200)
          .json(buildLegacyAuditReport(body, this.maliciousPackageStore));
      });
    });

    if (
      !this.blockPublishWithNewScripts &&
      !this.blockPublishMatches &&
      !this.sensitivePathsEnabled
    )
      return;

    // Workaround for verdaccio/verdaccio#1912 (reported 2020, unfixed in
    // the currently-published @verdaccio/middleware -- see
    // verdaccio-oidc-auth's own identical comment on its own copy of this
    // same fix for the full analysis). @verdaccio/middleware's own
    // access-log middleware attaches req.on('data', ...) unconditionally,
    // on every request, purely to count bytes -- switching the request
    // stream into Node's flowing mode immediately. Any async middleware
    // ahead of this plugin's own body-parser below (an authentication
    // plugin doing a real network-bound token check is the common case,
    // but this deployment cannot assume one is even installed, let alone
    // which one) opens a window where the stream can fully drain via that
    // listener alone before any body-parser -- this plugin's own,
    // Verdaccio core's, or another plugin's -- ever gets to attach its own.
    // This must not depend on any specific other plugin (e.g.
    // verdaccio-oidc-auth) being installed at all -- these plugins are
    // published and used independently, in any combination a deployment
    // chooses -- so this protects itself the same way, using body-parser's
    // own pre-existing req.body/req._body contract rather than a
    // plugin-specific signal: if some earlier middleware already populated
    // req.body (this plugin's own JSON parsing below already respects that
    // via body-parser's own req._body check), skip; otherwise read the
    // body synchronously as the very first thing here, before this
    // middleware's own path/segment parsing even runs.
    app.use((req, res, next) => {
      if (req._body) return next();
      const contentEncoding = (req.headers['content-encoding'] || '')
        .trim()
        .toLowerCase();
      if (
        req.method !== 'PUT' ||
        !/json/i.test(req.headers['content-type'] || '') ||
        (contentEncoding !== '' && contentEncoding !== 'identity')
      ) {
        return next();
      }
      const chunks = [];
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', () => {
        const raw = Buffer.concat(chunks);
        try {
          req.body = raw.length > 0 ? JSON.parse(raw.toString('utf8')) : {};
        } catch (err) {
          return next(err);
        }
        req._body = true;
        next();
      });
      req.on('error', err => next(err));
    });

    app.use((req, res, next) => {
      if (req.method !== 'PUT') return next();

      // Matches only the metadata PUT used for a fresh publish or a
      // version/tag update (`/:package` or `/:package/-rev/:revision`) --
      // not the separate tarball-only upload route
      // (`/:package/-/:filename/*`), which carries no `scripts` to inspect.
      const segments = req.path
        .replace(/\/%40/, '/@')
        .split('/')
        .filter(Boolean);
      if (segments.length === 0 || segments.length > 2 || segments[1] === '-')
        return next();
      const packageName = decodeURIComponent(segments[0]);

      // This middleware runs before Verdaccio's own API router installs its
      // express.json() body parser (see docs/plugins/security-filter.md's
      // "Publish-time gate" section for exactly where in the pipeline that
      // is), so req.body isn't populated yet -- parse it ourselves. This is
      // safe: body-parser sets req._body = true unconditionally as the
      // first thing it does (node_modules/body-parser/lib/read.js), and its
      // own json middleware skips re-parsing whenever that flag is already
      // set (node_modules/body-parser/lib/types/json.js) -- so Verdaccio's
      // later parse attempt becomes a no-op instead of double-reading an
      // already-drained request stream.
      this._parseJsonBody(req, res, err => {
        if (err) {
          // raw-body's own error carries expected/received/type properties
          // that never otherwise reach any log line (Verdaccio's own
          // request logger only captures err.message) -- surfacing them
          // here is the only way to see the byte-count discrepancy behind
          // a "request size did not match content length" failure, should
          // one ever happen again despite the buffering middleware above.
          this.logger.error(
            {
              pkg: packageName,
              errType: err.type,
              errMessage: err.message,
              expected: err.expected,
              received: err.received,
              length: err.length,
            },
            'security-filter: publish body parse failed (@{errType}: @{errMessage}, expected=@{expected} received=@{received})',
          );
          return next(err); // propagate straight to Verdaccio's own error handling
        }
        if (!req.body?.versions || typeof req.body.versions !== 'object')
          return next();
        this._checkPublish(req, res, next, storage, packageName);
      });
    });
  }

  _checkPublish(req, res, next, storage, packageName) {
    const incomingVersions = req.body.versions;

    storage.getPackage({
      name: packageName,
      uplinksLook: false,
      req,
      callback: async (err, existing) => {
        const existingVersions =
          !err && existing?.versions ? existing.versions : {};
        // Only versions this exact request would actually add -- robust to
        // whichever shape npm's client sends (just the new version, or the
        // full merged set including ones already stored).
        const newVersionKeys = Object.keys(incomingVersions).filter(
          v => !(v in existingVersions),
        );
        if (newVersionKeys.length === 0) return next(); // nothing new here (e.g. deprecate, star)

        const user = req.remote_user?.name;

        // Unconditional gate: a known-malicious or manually-blocked match is
        // a hard no regardless of package history -- unlike the
        // install-script check below, there's no "clean baseline"
        // precondition here, and it fires even for a brand-new package.
        if (this.blockPublishMatches) {
          for (const ver of newVersionKeys) {
            if (findMatchingRules(this.allowRules, packageName, ver).length > 0)
              continue;

            const osvHit = this.maliciousPackageStore?.check(packageName, ver);
            if (osvHit && osvHit.type === 'cve') {
              this.logger.fatal(
                {
                  pkg: packageName,
                  ver,
                  user,
                  cveId: osvHit.cveId,
                  severity: osvHit.severity,
                  cweIds: osvHit.cweIds,
                },
                'security-filter: !!! BLOCKED PUBLISH !!! @{pkg}@@{ver} by @{user} matches known vulnerability ' +
                  '@{cveId} [@{severity}, @{cweIds}] (OSV) -- rejected',
              );
              const cveReason =
                `SECURITY BLOCK: publish of ${packageName}@${ver} rejected -- matches known vulnerability ` +
                `${osvHit.cveId ?? osvHit.ids.join(', ')} (${osvHit.severity ?? 'unknown severity'}` +
                `${osvHit.cweIds?.length ? ', ' + osvHit.cweIds.join(', ') : ''}) from OSV. Contact a registry ` +
                'administrator if this is a false positive.';
              sendWebhook(
                this.webhookConfig,
                {
                  event: 'publish_blocked_cve',
                  pkg: packageName,
                  ver,
                  user,
                  cveId: osvHit.cveId,
                  severity: osvHit.severity,
                  cweIds: (osvHit.cweIds ?? []).join(', '),
                  reason: cveReason,
                },
                this.logger,
              );
              return res
                .status(403)
                .json({error: 'forbidden', reason: cveReason});
            }
            if (osvHit) {
              this.logger.fatal(
                {pkg: packageName, ver, user, malIds: osvHit.malIds},
                'security-filter: !!! BLOCKED PUBLISH !!! @{pkg}@@{ver} by @{user} matches known-malicious-package ' +
                  'advisory [@{malIds}] (OSV) -- rejected',
              );
              const malReason =
                `SECURITY BLOCK: publish of ${packageName}@${ver} rejected -- matches a known-malicious-package ` +
                `advisory (${osvHit.malIds.join(', ')}) from OSV. Contact a registry administrator if this is a ` +
                'false positive.';
              sendWebhook(
                this.webhookConfig,
                {
                  event: 'publish_blocked_mal',
                  pkg: packageName,
                  ver,
                  user,
                  malIds: osvHit.malIds.join(', '),
                  reason: malReason,
                },
                this.logger,
              );
              return res
                .status(403)
                .json({error: 'forbidden', reason: malReason});
            }

            const matchedBlockRules = findMatchingRules(
              this.blockRules,
              packageName,
              ver,
            );
            if (matchedBlockRules.length > 0) {
              const rule = matchedBlockRules.map(describeRule).join(', ');
              this.logger.fatal(
                {pkg: packageName, ver, user, rule},
                'security-filter: !!! BLOCKED PUBLISH !!! @{pkg}@@{ver} by @{user} matches manual block rule ' +
                  '[@{rule}] -- rejected',
              );
              const ruleReason = `SECURITY BLOCK: publish of ${packageName}@${ver} rejected -- matches manual block rule (${rule}).`;
              sendWebhook(
                this.webhookConfig,
                {
                  event: 'publish_blocked_rule',
                  pkg: packageName,
                  ver,
                  user,
                  rule,
                  reason: ruleReason,
                },
                this.logger,
              );
              return res
                .status(403)
                .json({error: 'forbidden', reason: ruleReason});
            }
          }
        }

        // Sensitive-path touch -- see filter_metadata()'s own version of this
        // check (5d) for the direct-only read-time equivalent; here, at
        // publish time, the tarball attachment is also available, so a
        // script that merely *invokes* another bundled file (rather than
        // touching the sensitive path inline) is caught too. Same
        // alert-vs-block shape as the obfuscation heuristics below --
        // deliberately placed ahead of the blockPublishWithNewScripts gate
        // just below, so `sensitivePaths.enabled` alone is enough to run
        // this check, independent of that unrelated flag.
        if (this.sensitivePathsEnabled) {
          // Gather every locally-referenced script file across all new
          // versions' install scripts up front, then do exactly one tarball
          // parse for all of them -- extractTarballFiles() is the only place
          // this plugin ever touches tarball bytes, gated entirely behind
          // this opt-in flag.
          const wantedFiles = new Set();
          for (const ver of newVersionKeys) {
            const scripts = incomingVersions[ver].scripts ?? {};
            for (const key of INSTALL_SCRIPTS) {
              for (const file of extractReferencedScriptFiles(scripts[key])) {
                wantedFiles.add(file);
              }
            }
          }

          // Missing/unreadable attachment is a silent empty result, same
          // "can't verify -- only the direct check still applies" degrade as
          // filter_metadata()'s own read-time check.
          let tarballFiles = null;
          if (wantedFiles.size > 0) {
            const attachmentBuffer = getAttachmentBuffer(
              req.body,
              packageName,
              newVersionKeys,
            );
            if (attachmentBuffer) {
              try {
                tarballFiles = await extractTarballFiles(
                  attachmentBuffer,
                  wantedFiles,
                );
              } catch (err) {
                this.logger.warn(
                  {pkg: packageName, err: err.message},
                  'security-filter: sensitivePaths -- failed to read tarball attachment, indirect check skipped',
                );
              }
            }
          }

          const blockableVersion = newVersionKeys.find(v => {
            if (findMatchingRules(this.allowRules, packageName, v).length > 0)
              return false;
            const hit = findSensitivePathTouch(
              incomingVersions[v],
              tarballFiles,
              this.sensitivePaths,
            );
            return !!hit && this.blockSensitivePathTouch;
          });

          if (blockableVersion) {
            const hit = findSensitivePathTouch(
              incomingVersions[blockableVersion],
              tarballFiles,
              this.sensitivePaths,
            );
            const detail =
              hit.type === 'direct'
                ? `references ${hit.matched} directly`
                : `invokes ${hit.file}, which itself references ${hit.matched}`;

            this.logger.fatal(
              {
                pkg: packageName,
                ver: blockableVersion,
                user,
                script: hit.key,
                detail,
              },
              'security-filter: !!! BLOCKED PUBLISH !!! @{pkg}@@{ver} by @{user} install script @{detail} -- rejected',
            );
            const pathReason =
              `SECURITY BLOCK: publish of ${packageName}@${blockableVersion} rejected -- its ${hit.key} ` +
              `script ${detail}, a credential/config/auto-run path it has no legitimate reason to touch. ` +
              'Contact a registry administrator if this is a false positive.';
            sendWebhook(
              this.webhookConfig,
              {
                event: 'publish_blocked_sensitive_path',
                pkg: packageName,
                ver: blockableVersion,
                user,
                detail,
                reason: pathReason,
              },
              this.logger,
            );
            return res
              .status(403)
              .json({error: 'forbidden', reason: pathReason});
          }

          for (const ver of newVersionKeys) {
            if (findMatchingRules(this.allowRules, packageName, ver).length > 0)
              continue;
            const hit = findSensitivePathTouch(
              incomingVersions[ver],
              tarballFiles,
              this.sensitivePaths,
            );
            if (!hit) continue;

            const detail =
              hit.type === 'direct'
                ? `references ${hit.matched} directly`
                : `invokes ${hit.file}, which itself references ${hit.matched}`;
            const alertReason = `${packageName}@${ver}'s ${hit.key} script ${detail} -- not blocked, review recommended.`;
            this.logger.warn(
              {pkg: packageName, ver, user, script: hit.key, detail},
              'security-filter: publish install script @{detail}, not blocked',
            );
            sendWebhook(
              this.webhookConfig,
              {
                event: 'publish_sensitive_path',
                pkg: packageName,
                ver,
                user,
                detail,
                reason: alertReason,
              },
              this.logger,
            );
          }
        }

        if (!this.blockPublishWithNewScripts) return next();

        // Existing install-script-introduction heuristic, unchanged, but
        // also allow-list-aware for consistency with the read path's full
        // precedence stack.
        if (hasCleanBaseline(existingVersions)) {
          const offendingVersion = newVersionKeys.find(
            v =>
              hasInstallScript(incomingVersions[v]) &&
              findMatchingRules(this.allowRules, packageName, v).length === 0,
          );
          if (offendingVersion) {
            const scripts = INSTALL_SCRIPTS.filter(
              s => s in (incomingVersions[offendingVersion].scripts ?? {}),
            );
            const commands = Object.fromEntries(
              scripts.map(s => [
                s,
                incomingVersions[offendingVersion].scripts[s],
              ]),
            );

            this.logger.fatal(
              {
                pkg: packageName,
                ver: offendingVersion,
                user,
                scripts,
                commands,
              },
              'security-filter: !!! BLOCKED PUBLISH !!! @{pkg}@@{ver} by @{user} introduces install script(s) ' +
                '[@{scripts}] not present in any previously published version -- rejected as a likely ' +
                'supply-chain compromise pattern',
            );

            const scriptReason =
              `SECURITY BLOCK: publish of ${packageName}@${offendingVersion} rejected -- it introduces install ` +
              `script(s) [${scripts.join(', ')}] that no previously published version of this package had. This ` +
              'is blocked as a likely supply-chain compromise pattern. Contact a registry administrator if this ' +
              'script is intentional.';
            sendWebhook(
              this.webhookConfig,
              {
                event: 'publish_blocked_script',
                pkg: packageName,
                ver: offendingVersion,
                user,
                scripts: scripts.join(', '),
                reason: scriptReason,
              },
              this.logger,
            );

            return res
              .status(403)
              .json({error: 'forbidden', reason: scriptReason});
          }
        }

        // Install-script content changed -- independent of hasCleanBaseline
        // above (that precondition only applies to the presence-only check;
        // see changedInstallScripts()'s own comment for why a package that's
        // always shipped a script is still worth checking here). Compares
        // against dist-tags.latest -- what a normal install would actually
        // get today -- not full publish history, keeping this a simple,
        // single comparison rather than its own historical scan.
        const latestExistingVersion = existing?.['dist-tags']?.latest;
        const previousVersionMeta = latestExistingVersion
          ? existingVersions[latestExistingVersion]
          : null;
        if (previousVersionMeta) {
          const offendingVersion = newVersionKeys.find(
            v =>
              changedInstallScripts(previousVersionMeta, incomingVersions[v])
                .length > 0 &&
              findMatchingRules(this.allowRules, packageName, v).length === 0,
          );
          if (offendingVersion) {
            const scripts = changedInstallScripts(
              previousVersionMeta,
              incomingVersions[offendingVersion],
            );
            const commands = Object.fromEntries(
              scripts.map(s => [
                s,
                incomingVersions[offendingVersion].scripts[s],
              ]),
            );

            this.logger.fatal(
              {
                pkg: packageName,
                ver: offendingVersion,
                user,
                scripts,
                commands,
              },
              'security-filter: !!! BLOCKED PUBLISH !!! @{pkg}@@{ver} by @{user} changed the content of ' +
                'existing install script(s) [@{scripts}] from the previously published version -- rejected ' +
                'as a likely supply-chain compromise pattern',
            );

            const scriptReason =
              `SECURITY BLOCK: publish of ${packageName}@${offendingVersion} rejected -- it changes the ` +
              `content of install script(s) [${scripts.join(', ')}] from ${packageName}@${latestExistingVersion}. ` +
              'This is blocked as a likely supply-chain compromise pattern. Contact a registry administrator ' +
              'if this change is intentional.';
            sendWebhook(
              this.webhookConfig,
              {
                event: 'publish_blocked_script_changed',
                pkg: packageName,
                ver: offendingVersion,
                user,
                scripts: scripts.join(', '),
                reason: scriptReason,
              },
              this.logger,
            );

            return res
              .status(403)
              .json({error: 'forbidden', reason: scriptReason});
          }
        }

        // Structural obfuscation heuristics -- see
        // classifySuspiciousScript()'s own comment for the confidence
        // ranking. Unlike the two checks above, a hit here is never a hard
        // reject unless it's the one high-confidence pattern AND
        // blockShellPipe is separately opted into -- everything else alerts
        // (webhook) but still lets the publish through, since these are
        // heuristics with a real false-positive rate, not the exact-match
        // certainty the OSV/manual-block/content-diff checks have.
        if (this.scriptHeuristicsEnabled) {
          const blockableVersion = newVersionKeys.find(v => {
            if (findMatchingRules(this.allowRules, packageName, v).length > 0)
              return false;
            const suspicious = findSuspiciousScript(incomingVersions[v]);
            return suspicious?.highConfidence && this.blockShellPipe;
          });
          if (blockableVersion) {
            const suspicious = findSuspiciousScript(
              incomingVersions[blockableVersion],
            );
            this.logger.fatal(
              {
                pkg: packageName,
                ver: blockableVersion,
                user,
                script: suspicious.key,
                hits: suspicious.hits,
              },
              'security-filter: !!! BLOCKED PUBLISH !!! @{pkg}@@{ver} by @{user} install script matches a ' +
                'high-confidence obfuscation/exfiltration pattern (@{hits}) -- rejected',
            );
            const patternReason =
              `SECURITY BLOCK: publish of ${packageName}@${blockableVersion} rejected -- its ` +
              `${suspicious.key} script matches a high-confidence obfuscation/exfiltration pattern ` +
              `(${suspicious.hits.join(', ')}). Contact a registry administrator if this is a false positive.`;
            sendWebhook(
              this.webhookConfig,
              {
                event: 'publish_blocked_suspicious_script',
                pkg: packageName,
                ver: blockableVersion,
                user,
                hits: suspicious.hits.join(', '),
                reason: patternReason,
              },
              this.logger,
            );
            return res
              .status(403)
              .json({error: 'forbidden', reason: patternReason});
          }

          for (const ver of newVersionKeys) {
            if (findMatchingRules(this.allowRules, packageName, ver).length > 0)
              continue;
            const suspicious = findSuspiciousScript(incomingVersions[ver]);
            if (!suspicious) continue;

            const alertReason =
              `${packageName}@${ver}'s ${suspicious.key} script matches a suspicious pattern ` +
              `(${suspicious.hits.join(', ')}) -- not blocked, review recommended.`;
            this.logger.warn(
              {
                pkg: packageName,
                ver,
                user,
                script: suspicious.key,
                hits: suspicious.hits,
              },
              'security-filter: publish install script matches a suspicious pattern (@{hits}), not blocked',
            );
            sendWebhook(
              this.webhookConfig,
              {
                event: 'publish_suspicious_script',
                pkg: packageName,
                ver,
                user,
                hits: suspicious.hits.join(', '),
                reason: alertReason,
              },
              this.logger,
            );
          }
        }

        next();
      },
    });
  }
}

module.exports = (config, options) => new SecurityFilter(config, options);
// Exported for the local smoke-test harness (test/smoke.js) -- not used by Verdaccio itself.
module.exports.SecurityFilter = SecurityFilter;
