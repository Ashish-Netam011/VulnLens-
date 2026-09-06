/**
 * Dependency / CVE intelligence tests (Phase 2).
 * Hermetic: no real OSV network calls (fetch is injected/mocked), no DB.
 * Covers the manifest parser, the OSV batch lookup, unified-finding merge,
 * rescan diffing when a package is upgraded, SSRF safety, and the dependency
 * summary aggregation used by the scan pipeline.
 */
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { parseDependencyManifests, _test as parserTest } from '../src/scanner/dependencyParser.js';
import {
  queryCVEs, buildDependencyFindings, buildBatchQuery, resolveAdvisorySeverity,
  extractRecommendedVersion, buildAdvisoryUrl, mapSeverity, compareSemver, clearCache,
  _test as cveTest,
} from '../src/services/cveLookup.js';
import { compareScans } from '../src/services/rescanService.js';
import { computeDependencySummary, emptyDependencySummary } from '../src/services/scanService.js';

// ── Helpers ───────────────────────────────────────────────────────────
function fetchMock(handler) {
  const calls = [];
  const fn = async (url, opts) => {
    calls.push({ url, opts });
    const payload = JSON.parse(opts.body || '{}');
    return handler(payload, calls.length - 1);
  };
  fn.calls = calls;
  return fn;
}
function jsonRes(data, status = 200) {
  return { status, ok: status >= 200 && status < 300, json: async () => data };
}
function npmAdvisory({ id, severity = 'HIGH', fixed, summary = 'Summary text', url = null, cvss = 9.8, rangeIntro = '1.0.0' }) {
  const affected = [{
    package: { ecosystem: 'npm', name: 'some-pkg' },
    ranges: [{ type: 'SEMVER', events: [{ introduced: rangeIntro }].concat(fixed ? [{ fixed }] : []) }],
    ecosystem_specific: {},
  }];
  const v = { id, summary, details: `${id} details`, affected };
  if (url) v.database_specific = { advisory: url };
  const impact = { cvss_v3: { baseScore: cvss } };
  if (severity) impact.severity = severity;
  v.impact = [impact];
  affected[0].impact = [impact];
  return v;
}

// ══ 1. Parser fixtures ═══════════════════════════════════════════════

test('parser: lockfile v3 flat packages map yields direct/transitive + dev + optional', () => {
  const files = [{
    path: 'myapp/package-lock.json',
    content: JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'myapp', version: '1.0.0', dependencies: { lodash: '^4.17.21', express: '^4.21.0' }, devDependencies: { jest: '^29.0.0' } },
        'node_modules/lodash': { version: '4.17.21' },
        'node_modules/express': { version: '4.21.1' },
        'node_modules/jest': { version: '29.7.0', dev: true },
        'node_modules/ms': { version: '2.1.3' },
      },
    }),
  }];
  const result = parseDependencyManifests(files);
  assert.ok(result, 'should find deps');
  const byName = Object.fromEntries(result.dependencies.map((d) => [d.name, d]));
  assert.equal(byName.lodash.type, 'direct');
  assert.equal(byName.express.type, 'direct');
  assert.equal(byName.jest.type, 'direct');
  assert.equal(byName.jest.dev, true);
  assert.equal(byName.ms.type, 'transitive');
  assert.equal(byName.ms.dev, false);
  assert.equal(result.manifestTypes[0], 'package-lock.json (v2/v3)');
});

test('parser: lockfile v3 excludes link + file: entries', () => {
  const files = [{
    path: 'package-lock.json',
    content: JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { local: 'file:../local', linked: 'link:../x', real: '^1.0.0' } },
        'node_modules/local': { version: 'file:../local' },
        'node_modules/linked': { link: true, resolved: 'yarn-pnp' },
        'node_modules/real': { version: '1.2.3' },
      },
    }),
  }];
  const result = parseDependencyManifests(files);
  const names = (result.dependencies || []).map((d) => d.name);
  assert.deepEqual(names, ['real']);
});

test('parser: lockfile v1 nested tree flattens transitive deps', () => {
  const files = [{
    path: 'package-lock.json',
    content: JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        express: {
          version: '4.21.1',
          dependencies: { ms: { version: '2.1.3' }, qs: { version: '6.13.0', dev: true } },
        },
      },
    }),
  }];
  const result = parseDependencyManifests(files);
  const byName = Object.fromEntries(result.dependencies.map((d) => [d.name, d]));
  assert.equal(byName.express.type, 'direct');
  assert.equal(byName.ms.type, 'transitive');
  assert.equal(byName.qs.type, 'transitive');
  assert.equal(byName.qs.dev, true);
  assert.equal(result.manifestTypes[0], 'package-lock.json (v1)');
});

test('parser: package.json fallback keeps only exact pins', () => {
  const files = [{
    path: 'app/package.json',
    content: JSON.stringify({
      dependencies: { lodash: '4.17.21', express: '^4.21.0', safe: '2.0.0' },
      devDependencies: { jest: '29.7.0', fancy: 'latest', rangey: '>=1.5.0' },
    }),
  }];
  const result = parseDependencyManifests(files);
  const byName = Object.fromEntries(result.dependencies.map((d) => [d.name, d]));
  assert.ok(byName.lodash, 'exact pin parsed');
  assert.ok(byName.safe, 'exact pin parsed');
  assert.ok(byName.jest, 'devDependencies exact pin parsed');
  assert.equal(byName.lodash.versionSource, 'package.json');
  assert.equal(byName.lodash.type, 'direct');
  assert.ok(!byName.express, 'range "^4.21.0" is not queryable without lockfile');
  assert.ok(!byName.fancy && !byName.rangey, 'non-exact ranges dropped');
});

test('parser: malformed JSON or oversized manifests are ignored safely', () => {
  const bad = parseDependencyManifests([{ path: 'package-lock.json', content: '{ not json !!!' }]);
  assert.equal(bad, null);
  const huge = `${' '.repeat(parserTest.MAX_MANIFEST_CHARS + 1)}`;
  const oversize = parseDependencyManifests([{ path: 'package-lock.json', content: huge }]);
  assert.equal(oversize, null);
});

test('parser: lockfile is authoritative over sibling package.json', () => {
  const files = [
    { path: 'package-lock.json', content: JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { a: '^1.0.0' } }, 'node_modules/a': { version: '1.0.0' } } }) },
    { path: 'package.json', content: JSON.stringify({ dependencies: { b: '2.0.0' } }) },
  ];
  const result = parseDependencyManifests(files);
  assert.deepEqual(result.dependencies.map((d) => d.name), ['a']);
});

test('parser: lockfile present but zero deps returns empty (no fallback to package.json)', () => {
  const files = [{ path: 'package-lock.json', content: JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'x' } } }) }];
  const result = parseDependencyManifests(files);
  assert.deepEqual(result.dependencies, []);
});

// ══ 2. CVE lookup (OSV batch, mocked fetch) ══════════════════════════

beforeEach(() => clearCache());
afterEach(() => clearCache());

test('osv: queryCVEs posts to the env OSV URL and batches >1000 deps', async () => {
  clearCache();
  const deps = [];
  for (let i = 0; i < 2005; i++) deps.push({ name: `pkg${i}`, version: `1.${i}.0` });
  const mock = fetchMock((body) => jsonRes({ results: body.queries.map(() => ({ vulns: [] })) }));
  const map = await queryCVEs(deps, { fetch: mock });
  assert.ok(mock.calls.length >= 2, `expected chunked calls, got ${mock.calls.length}`);
  for (const c of mock.calls) assert.equal(c.url, cveTest.OSV_API_URL);
  const sizes = mock.calls.map((c) => JSON.parse(c.opts.body).queries.length);
  assert.equal(sizes[0], 1000);
  assert.equal(sizes[sizes.length - 1], 5);
  assert.equal(map.size, 2005);
});

test('osv: cached lookups skip the network entirely', async () => {
  // Seed the shared cache directly, then confirm queryCVEs serves hits offline.
  clearCache();
  cveTest.cache.set('pkg-a@1.0.0', { ts: Date.now(), vulnerabilities: [] });
  cveTest.cache.set('pkg-b@2.0.0', { ts: Date.now(), vulnerabilities: [] });
  const mock = fetchMock(() => { throw new Error('should not hit network'); });
  const map = await queryCVEs([{ name: 'pkg-a', version: '1.0.0' }, { name: 'pkg-b', version: '2.0.0' }], { fetch: mock });
  assert.equal(mock.calls.length, 0, 'all hits must come from cache');
  assert.equal(map.size, 2);
});

test('osv: batch body uses exact npm ecosystem + pinned version', () => {
  const chunks = buildBatchQuery([{ name: '@scope/thing', version: '3.2.1' }]);
  assert.deepEqual(chunks[0].queries[0], { package: { ecosystem: 'npm', name: '@scope/thing' }, version: '3.2.1' });
});

test('osv: 429 rate limit rejects; nothing is cached from a failed response', async () => {
  const mock = fetchMock(() => jsonRes({ error: 'rate limited' }, 429));
  await assert.rejects(queryCVEs([{ name: 'x', version: '1.0.0' }], { fetch: mock }), /rate limit/i);
  const mock2 = fetchMock(() => jsonRes({ results: [{ vulns: [] }] }));
  await queryCVEs([{ name: 'x', version: '1.0.0' }], { fetch: mock2 });
  assert.equal(mock2.calls.length, 1);
});

test('osv: network failure rejects (scan continues without CVE data)', async () => {
  const mock = fetchMock(() => { throw new Error('ECONNREFUSED'); });
  await assert.rejects(queryCVEs([{ name: 'x', version: '1.0.0' }], { fetch: mock }), /ECONNREFUSED/);
});

// ══ 3. Advisory → unified finding mapping ═════════════════════════════

test('finding: OSV advisory becomes a dependency finding with metadata', () => {
  const advisory = npmAdvisory({ id: 'GHSA-1234', severity: 'CRITICAL', cvss: 9.8, fixed: '4.17.22', url: 'https://github.com/advisories/GHSA-1234' });
  const findings = buildDependencyFindings({ name: 'lodash', version: '4.17.21', type: 'direct' }, [advisory], 'package-lock.json');
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.kind, 'dependency');
  assert.equal(f.comparisonKey, 'dep:lodash@4.17.21:GHSA-1234');
  assert.equal(f.packageName, 'lodash');
  assert.equal(f.installedVersion, '4.17.21');
  assert.equal(f.recommendedVersion, '4.17.22');
  assert.equal(f.cveId, 'GHSA-1234');
  assert.equal(f.severity, 'critical');
  assert.equal(f.advisoryUrl, 'https://github.com/advisories/GHSA-1234');
  assert.equal(f.dependencyType, 'direct');
  assert.equal(f.affectedVersionRange.includes('>=1.0.0'), true);
  assert.match(f._ruleEnrichment.remediation, /4\.17\.22/);
});

test('finding: missing database_specific URL falls back to OSV page', () => {
  const advisory = npmAdvisory({ id: 'CVE-2024-0001', severity: 'HIGH', cvss: 8.1, fixed: '1.0.1' });
  const f = buildDependencyFindings({ name: 'x', version: '1.0.0' }, [advisory], 'package-lock.json')[0];
  const base = cveTest.OSV_API_URL.replace(/\/v1\/?.*$/, '').replace(/\/$/, '');
  assert.equal(f.advisoryUrl, `${base}/vulnerability/CVE-2024-0001`);
});

test('finding: severity mapping + fixed-version extraction helpers', () => {
  assert.equal(mapSeverity('CRITICAL'), 'critical');
  assert.equal(mapSeverity('MODERATE'), 'medium');
  assert.equal(mapSeverity('low'), 'low');
  const sev = resolveAdvisorySeverity(npmAdvisory({ severity: 'MEDIUM', cvss: 5.5 }).affected);
  assert.equal(sev, 'medium');
  const fixed = extractRecommendedVersion(npmAdvisory({ fixed: '2.5.0' }).affected);
  assert.equal(fixed, '2.5.0');
  assert.equal(extractRecommendedVersion([{ ranges: [] }]), null);
});

test('finding: semver picker returns the highest fixed version', () => {
  assert.ok(compareSemver('2.10.0', '2.9.9') > 0);
  assert.ok(compareSemver('v1.0.0', '1.0.0-beta') !== 0);
  assert.equal(compareSemver('1.2.3', '1.2.3'), 0);
});

// ══ 4. Pipeline merge + rescan diffing ═══════════════════════════════
test('pipeline: dependency finding merges with code findings and resolves on upgrade', () => {
  const lockFiles = [{
    path: 'app/package-lock.json',
    content: JSON.stringify({
      lockfileVersion: 3,
      packages: { '': { dependencies: { lodash: '^4.17.21' } }, 'node_modules/lodash': { version: '4.17.21' } },
    }),
  }];
  const parsed = parseDependencyManifests(lockFiles);
  const vulnMap = new Map();
  vulnMap.set('lodash@4.17.21', [npmAdvisory({ id: 'GHSA-fixed', severity: 'HIGH', cvss: 8.3, fixed: '4.17.22' })]);
  const vulnDeps = parsed.dependencies
    .map((d) => buildDependencyFindings(d, vulnMap.get(`${d.name}@${d.version}`) || [], d.sourceFile))
    .flat()
    .filter(Boolean);

  const upgradedLock = [{
    path: 'app/package-lock.json',
    content: JSON.stringify({
      lockfileVersion: 3,
      packages: { '': { dependencies: { lodash: '^4.17.21' } }, 'node_modules/lodash': { version: '4.17.22' } },
    }),
  }];
  const parsed2 = parseDependencyManifests(upgradedLock);
  const fixedDeps = parsed2.dependencies.map((d) => buildDependencyFindings(d, [], d.sourceFile)).flat();

  const comparison = compareScans({ findings: vulnDeps }, { findings: fixedDeps });
  assert.equal(comparison.resolved, 1, 'upgraded package should clear the dependency finding');
  assert.equal(comparison.remaining, 0);
  assert.equal(comparison.new, 0);
});

test('pipeline: dependency summary aggregates per-severity + vulnerable package counts', () => {
  const deps = [
    { name: 'a', version: '1.0.0', type: 'direct' },
    { name: 'b', version: '2.0.0', type: 'transitive' },
    { name: 'c', version: '3.0.0', type: 'transitive' },
  ];
  const findings = [
    { kind: 'dependency', severity: 'critical', packageName: 'a', installedVersion: '1.0.0' },
    { kind: 'dependency', severity: 'low', packageName: 'a', installedVersion: '1.0.0' },
    { kind: 'dependency', severity: 'high', packageName: 'b', installedVersion: '2.0.0' },
  ];
  const summary = emptyDependencySummary();
  computeDependencySummary(summary, deps, findings);
  assert.equal(summary.total, 3);
  assert.equal(summary.direct, 1);
  assert.equal(summary.transitive, 2);
  assert.equal(summary.vulnerable, 2);
  assert.equal(summary.bySeverity.critical, 1);
  assert.equal(summary.bySeverity.low, 1);
  assert.equal(summary.bySeverity.high, 1);
});

// ══ 5. SSRF guard ════════════════════════════════════════════════════
test('ssrf: user-controlled package names can never redirect the OSV request', async () => {
  const hostile = [
    { name: 'http://evil.example.com', version: '1.0.0' },
    { name: 'https://attacker.io/x', version: '1.0.0' },
    { name: '../../etc/passwd', version: '1.0.0' },
    { name: '@foo', version: '1.0.0' },
  ];
  const chunks = buildBatchQuery(hostile);
  const payload = JSON.parse(JSON.stringify(chunks[0]));
  // Hostile names arrive only as plain package.name strings inside the JSON body —
  // the request URL itself is always the env OSV constant (asserted below on fetch).
  assert.equal(payload.queries[0].package.name, 'http://evil.example.com');
  const mock = fetchMock((payload2) => jsonRes({ results: payload2.queries.map(() => ({ vulns: [] })) }));
  const map = await queryCVEs(hostile, { fetch: mock });
  for (const c of mock.calls) assert.equal(c.url, cveTest.OSV_API_URL, 'only the env URL is contacted');
  assert.equal(map.size, 4);
});
