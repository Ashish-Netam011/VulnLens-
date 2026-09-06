/**
 * SARIF 2.1.0 reporting tests (Phase 3).
 * DB-free: pure generator functions are exercised directly, and the DB-aware
 * generateSarif wrapper is tested by stubbing Scan.findById (matching the
 * pattern used in security.test.js).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSarifReport,
  buildResult,
  buildRule,
  buildRules,
  severityToSarifLevel,
  normalizeSarifPath,
  fingerprintFor,
  serializeSarif,
  generateSarif,
  SARIF_VERSION,
  SARIF_SCHEMA,
} from '../src/services/sarifService.js';
import Scan from '../src/models/Scan.js';

function codeFinding(overrides = {}) {
  return {
    ruleId: 'hardcoded-apiKey',
    vulnerabilityType: 'Hardcoded Secret',
    title: 'Hardcoded API key detected',
    description: 'A static credential was found in source.',
    reason: 'Secrets should be loaded from environment variables.',
    severity: 'high',
    category: 'secrets',
    confidence: 'high',
    line: 17,
    column: 5,
    endLine: 17,
    filePath: 'src/config.js',
    affectedCode: 'const key = "sk-live-12345"',
    comparisonKey: 'src/config.js:17:hardcoded-apiKey',
    kind: 'code',
    ...overrides,
  };
}

function depFinding(overrides = {}) {
  return {
    ruleId: 'osv-advisory',
    title: 'Vulnerable dependency lodash',
    severity: 'critical',
    kind: 'dependency',
    packageName: 'lodash',
    installedVersion: '4.17.20',
    dependencyType: 'direct',
    cveId: 'CVE-2021-23337',
    affectedVersionRange: '<4.17.21',
    recommendedVersion: '4.17.21',
    advisoryUrl: 'https://osv.dev/vulnerability/CVE-2021-23337',
    filePath: 'package.json',
    line: 14,
    comparisonKey: 'package.json:14:osv-advisory:lodash',
    ...overrides,
  };
}

// ── 1. Valid SARIF 2.1.0 structure ───────────────────────────────────
test('sarif: produces a valid top-level 2.1.0 document with runs', () => {
  const sarif = buildSarifReport({ findings: [codeFinding()] });
  assert.equal(sarif.version, SARIF_VERSION);
  assert.equal(sarif['$schema'], SARIF_SCHEMA);
  assert.ok(Array.isArray(sarif.runs) && sarif.runs.length === 1);
  const run = sarif.runs[0];
  assert.ok(run.tool);
  assert.ok(Array.isArray(run.results));
  // Round-trips through JSON without error.
  assert.doesNotThrow(() => JSON.parse(serializeSarif(sarif)));
});

// ── 2. Tool / driver metadata ────────────────────────────────────────
test('sarif: tool driver exposes stable VulnLens metadata', () => {
  const driver = buildSarifReport({ findings: [codeFinding()] }).runs[0].tool.driver;
  assert.equal(driver.name, 'VulnLens');
  assert.equal(driver.version, '1.3.0');
  assert.equal(driver.semanticVersion, '1.3.0');
  assert.ok(Array.isArray(driver.rules) && driver.rules.length >= 1);
});

// ── 3. Code finding conversion ───────────────────────────────────────
test('sarif: code finding maps to result with ruleId/level/message/location', () => {
  const result = buildResult(codeFinding());
  assert.equal(result.ruleId, 'hardcoded-apiKey');
  assert.equal(result.level, 'error');
  assert.equal(result.message.text, 'Hardcoded API key detected');
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, 'src/config.js');
  assert.equal(result.locations[0].physicalLocation.region.startLine, 17);
  assert.equal(result.locations[0].physicalLocation.region.startColumn, 5);
  assert.equal(result.locations[0].physicalLocation.region.endLine, 17);
  assert.equal(result.properties.kind, 'code');
  assert.equal(result.properties.vulnerabilityType, 'Hardcoded Secret');
  assert.equal(result.properties.confidence, 'high');
});

// ── 4. Dependency finding conversion ─────────────────────────────────
test('sarif: dependency finding maps to result with populated dependency metadata', () => {
  const result = buildResult(depFinding());
  assert.equal(result.ruleId, 'osv-advisory');
  assert.equal(result.level, 'error');
  assert.equal(result.properties.kind, 'dependency');
  assert.equal(result.properties.packageName, 'lodash');
  assert.equal(result.properties.installedVersion, '4.17.20');
  assert.equal(result.properties.dependencyType, 'direct');
  assert.equal(result.properties.cve, 'CVE-2021-23337');
  assert.equal(result.properties.affectedRange, '<4.17.21');
  assert.equal(result.properties.fixedVersion, '4.17.21');
  assert.equal(result.properties.advisoryUrl, 'https://osv.dev/vulnerability/CVE-2021-23337');
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, 'package.json');
});

// ── 5-9. Deterministic severity mapping ──────────────────────────────
test('sarif: severity mapping is deterministic (critical/high→error, medium→warning, low/info→note)', () => {
  assert.equal(severityToSarifLevel('critical'), 'error');
  assert.equal(severityToSarifLevel('high'), 'error');
  assert.equal(severityToSarifLevel('medium'), 'warning');
  assert.equal(severityToSarifLevel('low'), 'note');
  assert.equal(severityToSarifLevel('informational'), 'note');
  // Case-insensitive.
  assert.equal(severityToSarifLevel('HIGH'), 'error');
  assert.equal(severityToSarifLevel('Medium'), 'warning');
});

test('sarif: severity from finding is reflected into result.level', () => {
  assert.equal(buildResult(codeFinding({ severity: 'critical' })).level, 'error');
  assert.equal(buildResult(codeFinding({ severity: 'high' })).level, 'error');
  assert.equal(buildResult(codeFinding({ severity: 'medium' })).level, 'warning');
  assert.equal(buildResult(codeFinding({ severity: 'low' })).level, 'note');
  assert.equal(buildResult(codeFinding({ severity: 'informational' })).level, 'note');
});

// ── 10-12. File path / line mapping ──────────────────────────────────
test('sarif: relative posix file path maps to artifactLocation.uri', () => {
  const r = buildResult(codeFinding({ filePath: 'src/auth/login.js' }));
  assert.equal(r.locations[0].physicalLocation.artifactLocation.uri, 'src/auth/login.js');
});

test('sarif: line number maps to region.startLine', () => {
  const r = buildResult(codeFinding({ line: 42 }));
  assert.equal(r.locations[0].physicalLocation.region.startLine, 42);
});

test('sarif: missing line number omits the region but keeps the location', () => {
  const r = buildResult(codeFinding({ line: undefined, column: undefined, endLine: undefined }));
  assert.ok(r.locations && r.locations.length === 1);
  assert.equal(r.locations[0].physicalLocation.region, undefined);
});

test('sarif: missing file path still yields a valid result with fingerprint', () => {
  const r = buildResult(codeFinding({ filePath: '' }));
  assert.equal(r.locations, undefined);
  assert.ok(r.partialFingerprints.primaryLocationLineHash);
});

// ── 13. Stable fingerprints ──────────────────────────────────────────
test('sarif: fingerprints are stable for unchanged comparisonKey', () => {
  const a = fingerprintFor(codeFinding({ comparisonKey: 'src/config.js:17:hardcoded-apiKey' }));
  const b = fingerprintFor(codeFinding({ comparisonKey: 'src/config.js:17:hardcoded-apiKey' }));
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{32}$/);
});

test('sarif: fingerprints differ when comparisonKey differs', () => {
  const a = fingerprintFor(codeFinding({ comparisonKey: 'x:1' }));
  const b = fingerprintFor(codeFinding({ comparisonKey: 'y:1' }));
  assert.notEqual(a, b);
});

// ── 14-15. Folder findings / identical snippets in different files ──
test('sarif: identical snippets in different files stay separate results', () => {
  const a = codeFinding({ filePath: 'src/a.js', comparisonKey: 'src/a.js:17:hardcoded-apiKey' });
  const b = codeFinding({ filePath: 'src/b.js', comparisonKey: 'src/b.js:17:hardcoded-apiKey' });
  const sarif = buildSarifReport({ findings: [a, b] });
  assert.equal(sarif.runs[0].results.length, 2);
  const uris = sarif.runs[0].results.map((r) => r.locations[0].physicalLocation.artifactLocation.uri);
  assert.deepEqual(uris.sort(), ['src/a.js', 'src/b.js']);
  const hashes = sarif.runs[0].results.map((r) => r.partialFingerprints.primaryLocationLineHash);
  assert.notEqual(hashes[0], hashes[1], 'fingerprints must differ across files');
});

test('sarif: folder scan produces one result per finding', () => {
  const sarif = buildSarifReport({
    findings: [
      codeFinding({ filePath: 'src/a.js', comparisonKey: 'a:1' }),
      codeFinding({ filePath: 'src/b.js', comparisonKey: 'b:1' }),
      depFinding(),
    ],
  });
  assert.equal(sarif.runs[0].results.length, 3);
});

// ── 16-17. Dependency / CVE metadata ─────────────────────────────────
test('sarif: dependency metadata block is present and complete', () => {
  const r = buildResult(depFinding());
  assert.deepEqual(r.properties, {
    kind: 'dependency',
    packageName: 'lodash',
    installedVersion: '4.17.20',
    dependencyType: 'direct',
    cve: 'CVE-2021-23337',
    affectedRange: '<4.17.21',
    fixedVersion: '4.17.21',
    advisoryUrl: 'https://osv.dev/vulnerability/CVE-2021-23337',
  });
});

test('sarif: empty dependency metadata is safely omitted', () => {
  const r = buildResult(depFinding({ packageName: '', installedVersion: undefined, cveId: null }));
  assert.equal(r.properties.packageName, undefined);
  assert.equal(r.properties.cve, undefined);
});

// ── 17b. Baseline regression status (Phase 6D) ─────────────────────
test('sarif: baselineStatus is exposed in result properties', () => {
  const r = buildResult(codeFinding({ baselineStatus: 'BASELINED' }));
  assert.equal(r.properties.baselineStatus, 'BASELINED');
});

test('sarif: baselineStatus is absent when the finding was not classified', () => {
  const r = buildResult(codeFinding());
  assert.equal(r.properties.baselineStatus, undefined);
  assert.equal(r.properties.baselineEscalated, undefined);
});

test('sarif: escalated baselined findings keep their status and severity', () => {
  const r = buildResult(codeFinding({ baselineStatus: 'BASELINED', baselineEscalated: true, severity: 'critical' }));
  assert.equal(r.properties.baselineStatus, 'BASELINED');
  assert.equal(r.properties.baselineEscalated, true);
  assert.equal(r.level, 'error', 'severity must map to SARIF level unchanged');
});

// ── 18. Empty findings ───────────────────────────────────────────────
test('sarif: empty scan produces valid SARIF with empty results[]', () => {
  const sarif = buildSarifReport({ findings: [] });
  assert.deepEqual(sarif.runs[0].results, []);
  assert.equal(sarif.runs[0].tool.driver.rules, undefined);
  assert.doesNotThrow(() => JSON.parse(serializeSarif(sarif)));
});

test('sarif: scan object without findings array is treated as empty', () => {
  const sarif = buildSarifReport({});
  assert.deepEqual(sarif.runs[0].results, []);
});

// ── 19. Multiple findings ────────────────────────────────────────────
test('sarif: multiple mixed findings produce aligned results and deduplicated rules', () => {
  const findings = [
    codeFinding(),
    codeFinding({ title: 'Another hardcoded secret', comparisonKey: 'z:2' }),
    depFinding(),
  ];
  const sarif = buildSarifReport({ findings });
  assert.equal(sarif.runs[0].results.length, 3);
  const ruleIds = sarif.runs[0].results.map((r) => r.ruleId);
  assert.ok(ruleIds.includes('hardcoded-apiKey'));
  assert.ok(ruleIds.includes('osv-advisory'));
  const ids = sarif.runs[0].tool.driver.rules.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
});

// ── Rule definitions ─────────────────────────────────────────────────
test('sarif: driver.rules exposes stable rule metadata without secrets', () => {
  const rules = buildRules([codeFinding(), codeFinding({ comparisonKey: 'dup' })]);
  assert.equal(rules.length, 1);
  const rule = rules[0];
  assert.equal(rule.id, 'hardcoded-apiKey');
  assert.equal(rule.name, 'Hardcoded Secret');
  assert.equal(rule.shortDescription.text, 'Hardcoded API key detected');
  assert.equal(rule.fullDescription.text, 'A static credential was found in source.');
  assert.equal(rule.help.text, 'Secrets should be loaded from environment variables.');
  assert.equal(rule.defaultConfiguration.level, 'error');
});

test('sarif: buildRule falls back gracefully on missing metadata', () => {
  const rule = buildRule({ ruleId: 'x' });
  assert.equal(rule.id, 'x');
  assert.equal(rule.name, 'Security Finding');
  assert.equal(rule.shortDescription.text, 'Security Finding');
  assert.equal(rule.defaultConfiguration.level, 'note');
});

// ── 20. Secret masking ───────────────────────────────────────────────
test('sarif: raw secrets and affectedCode never appear in output', () => {
  const secret = 'sk-live-SECRET123-RAW';
  const finding = codeFinding({
    affectedCode: `const key = "${secret}"`,
    comparisonKey: `src/config.js:17:hardcoded-apiKey:${secret}`,
  });
  finding.rawValue = secret; // hostile field a generator might accidentally read
  const serialized = serializeSarif(buildSarifReport({ findings: [finding] }));
  assert.ok(!serialized.includes(secret), 'raw secret leaked into SARIF');
  assert.ok(!serialized.includes('sk-live'), 'masked pattern leaked into SARIF');
});

// ── 21. Windows path normalization ───────────────────────────────────
test('sarif: Windows absolute path is normalized to a safe relative URI', () => {
  const out = normalizeSarifPath('C:\\Users\\Ashish\\Desktop\\vulnlens\\backend\\uploads\\src\\auth\\login.js');
  // Drive letter and leading backslash are stripped, separators normalized,
  // and the personal homedir "Users/<name>" prefix removed.
  assert.equal(out, 'Desktop/vulnlens/backend/uploads/src/auth/login.js');
  assert.ok(!out.includes('C:'));
  assert.ok(!out.includes('\\'));
  assert.ok(!out.includes('Users'));
});

test('sarif: mixed Windows/unix separators normalize consistently', () => {
  assert.equal(normalizeSarifPath('backend\\src\\main.js'), 'backend/src/main.js');
  assert.equal(normalizeSarifPath('src\\auth/login.js'), 'src/auth/login.js');
});

// ── 22. Absolute path protection ─────────────────────────────────────
test('sarif: leading-slash absolute paths are stripped to relative', () => {
  assert.equal(normalizeSarifPath('/etc/passwd'), 'etc/passwd');
  assert.equal(normalizeSarifPath('/home/ashish/src/a.js'), 'src/a.js');
});

test('sarif: traversal segments are removed', () => {
  assert.equal(normalizeSarifPath('../../etc/../src/a.js'), 'etc/src/a.js');
});

test('sarif: empty/whitespace/null paths normalize to empty string', () => {
  assert.equal(normalizeSarifPath(''), '');
  assert.equal(normalizeSarifPath('   '), '');
  assert.equal(normalizeSarifPath(null), '');
  assert.equal(normalizeSarifPath(undefined), '');
});

// ── 23. Unknown severity handling ────────────────────────────────────
test('sarif: unknown/absent severity falls back to note', () => {
  assert.equal(severityToSarifLevel('blurry'), 'note');
  assert.equal(severityToSarifLevel(undefined), 'note');
  assert.equal(severityToSarifLevel(''), 'note');
  assert.equal(buildResult(codeFinding({ severity: undefined })).level, 'note');
});

// ── 24. Unknown finding kind handling ────────────────────────────────
test('sarif: unknown finding kind is treated as code, not a crash', () => {
  const r = buildResult(codeFinding({ kind: 'mystery' }));
  assert.equal(r.properties.kind, 'code');
  assert.doesNotThrow(() => buildSarifReport({ findings: [codeFinding({ kind: null })] }));
});

test('sarif: result never throws on incomplete finding data', () => {
  const r = buildResult(null);
  assert.equal(r.ruleId, 'unknown-rule');
  assert.equal(r.level, 'note');
  assert.ok(r.partialFingerprints.primaryLocationLineHash);
});

// ── API-level: generateSarif ownership / not-found ───────────────────
test('generateSarif: non-owner is forbidden (403)', async () => {
  const prev = Scan.findById;
  Scan.findById = () => ({ exec: async () => ({ _id: 's1', owner: 'ownerA', findings: [codeFinding()] }) });
  try {
    await assert.rejects(
      () => generateSarif('507f1f77bcf86cd799439011', 'ownerB'),
      (err) => err.status === 403
    );
  } finally {
    Scan.findById = prev;
  }
});

test('generateSarif: missing scan returns 404', async () => {
  const prev = Scan.findById;
  Scan.findById = () => ({ exec: async () => null });
  try {
    await assert.rejects(
      () => generateSarif('507f1f77bcf86cd799439011', 'ownerA'),
      (err) => err.status === 404
    );
  } finally {
    Scan.findById = prev;
  }
});

test('generateSarif: owner can generate a full SARIF report', async () => {
  const prev = Scan.findById;
  Scan.findById = () => ({ exec: async () => ({ _id: 's1', owner: 'ownerA', findings: [codeFinding(), depFinding()] }) });
  try {
    const sarif = await generateSarif('507f1f77bcf86cd799439011', 'ownerA');
    assert.equal(sarif.version, SARIF_VERSION);
    assert.equal(sarif.runs[0].results.length, 2);
  } finally {
    Scan.findById = prev;
  }
});

// ── Controller-level: downloadSarif endpoint behavior ────────────────
import { downloadSarif } from '../src/controllers/reportController.js';

function makeRes() {
  const headers = {};
  return {
    headers,
    body: null,
    setHeader(k, v) {
      headers[k] = v;
      return this;
    },
    send(b) {
      this.body = b;
      return this;
    },
  };
}

test('downloadSarif: owner receives application/sarif+json with attachment header', async () => {
  const prev = Scan.findById;
  Scan.findById = () => ({
    exec: async () => ({ _id: 's1', owner: 'ownerA', findings: [codeFinding()] }),
  });
  const res = makeRes();
  try {
    await downloadSarif({ params: { id: '507f1f77bcf86cd799439011' }, userId: 'ownerA' }, res, () => assert.fail('should not next'));
    assert.equal(res.headers['Content-Type'], 'application/sarif+json');
    assert.equal(
      res.headers['Content-Disposition'],
      'attachment; filename="vulnlens-scan-507f1f77bcf86cd799439011.sarif"'
    );
    const parsed = JSON.parse(res.body);
    assert.equal(parsed.version, SARIF_VERSION);
    assert.equal(parsed.runs[0].results.length, 1);
  } finally {
    Scan.findById = prev;
  }
});

test('downloadSarif: non-owner is rejected via the centralized error handler', async () => {
  const prev = Scan.findById;
  Scan.findById = () => ({ exec: async () => ({ _id: 's1', owner: 'ownerA', findings: [] }) });
  let nextErr = null;
  const res = makeRes();
  try {
    await downloadSarif({ params: { id: '507f1f77bcf86cd799439011' }, userId: 'ownerB' }, res, (e) => {
      nextErr = e;
    });
    assert.ok(nextErr);
    assert.equal(nextErr.status, 403);
  } finally {
    Scan.findById = prev;
  }
});

test('downloadSarif: missing scan is rejected (404) via next()', async () => {
  const prev = Scan.findById;
  Scan.findById = () => ({ exec: async () => null });
  let nextErr = null;
  const res = makeRes();
  try {
    await downloadSarif({ params: { id: '507f1f77bcf86cd799439011' }, userId: 'ownerA' }, res, (e) => {
      nextErr = e;
    });
    assert.ok(nextErr);
    assert.equal(nextErr.status, 404);
  } finally {
    Scan.findById = prev;
  }
});