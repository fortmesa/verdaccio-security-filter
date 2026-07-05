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

    for (const ver of sortedByAge) {
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
        const strategy = matchedBlockRules.every(r => r.strategy === 'replace')
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

      if (!isScripted) {
        seenCleanVersion = true;
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

  // Publish-time gates: REJECT (not just hide) a publish that either
  // introduces a preinstall/install/postinstall script not present in any
  // version this registry already has stored for that package
  // (blockPublishWithNewScripts), or matches the OSV malicious-package
  // blocklist or a manual block: rule (blockPublishMatches) -- whether the
  // target is an internal @fortmesa/* package or one that also proxies
  // reads to npmjs via '**'; both run on the publish path itself, before
  // storage, so they apply identically regardless of which `packages:`
  // pattern the name matches.
  //
  // Requires this plugin to ALSO be listed under `middlewares:` in
  // config.yaml with at least one of the two flags set true -- the
  // `filters:` role above is independent and unaffected either way.
  register_middlewares(app, auth, storage) {
    // Unconditional, regardless of the two flags below: this is the only
    // Verdaccio hook that ever receives a `storage` reference, and the OSV
    // singleton's own retroactive-match check (see malicious-packages.js's
    // _checkAgainstLocalStorage()) needs it independently of whether the
    // publish-time reject gates are also enabled here.
    this.maliciousPackageStore?.attachRegistryStorage?.(storage);

    if (!this.blockPublishWithNewScripts && !this.blockPublishMatches) return;

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
        if (err) return next(err); // propagate straight to Verdaccio's own error handling
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
      callback: (err, existing) => {
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

        // Existing install-script-introduction heuristic, unchanged, but
        // also allow-list-aware for consistency with the read path's full
        // precedence stack.
        if (!this.blockPublishWithNewScripts) return next();
        if (!hasCleanBaseline(existingVersions)) return next();
        const offendingVersion = newVersionKeys.find(
          v =>
            hasInstallScript(incomingVersions[v]) &&
            findMatchingRules(this.allowRules, packageName, v).length === 0,
        );
        if (!offendingVersion) return next();

        const scripts = INSTALL_SCRIPTS.filter(
          s => s in (incomingVersions[offendingVersion].scripts ?? {}),
        );
        const commands = Object.fromEntries(
          scripts.map(s => [s, incomingVersions[offendingVersion].scripts[s]]),
        );

        this.logger.fatal(
          {pkg: packageName, ver: offendingVersion, user, scripts, commands},
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

        res.status(403).json({error: 'forbidden', reason: scriptReason});
      },
    });
  }
}

module.exports = (config, options) => new SecurityFilter(config, options);
// Exported for the local smoke-test harness (test/smoke.js) -- not used by Verdaccio itself.
module.exports.SecurityFilter = SecurityFilter;
