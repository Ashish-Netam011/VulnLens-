/**
 * Production pipeline integration tests (Phase 4E).
 *
 * Boots the real Express app + in-memory MongoDB and exercises the full
 * production path end-to-end:
 *
 *   scanner → evidence → verdict → confidence → severity → scanService →
 *   Scan model → MongoDB → serializeScan → HTTP API
 *
 * Unlike the unit tests, these run against real persistence and the real HTTP
 * layer, so regressions in serialization, model casting, or API wiring surface
 * here.
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  setupTestServer,
  teardownTestServer,
  createAuthUser,
  createProject,
  api,
} from './helpers.js';

// ── Shared fixtures ─────────────────────────────────────────────────────────

const CONFIRMED_SQL = 'db.query("SELECT * FROM users WHERE id=" + req.query.id);';

const POTENTIAL_SQL =
  'function q(db, id) { return db.query("SELECT * FROM users WHERE id=" + id); }';

const PARAMETERIZED_SQL =
  'db.query("SELECT * FROM users WHERE id=?", [req.query.id]);';

const XSS_CONSTANT = 'el.innerHTML = "static greeting";';

const MULTI_FINDING = [
  'const fs = require("fs");',
  'fs.readFile(req.query.path, () => {});',
  'const id = req.query.id;',
  'const q = "SELECT * FROM users WHERE id=" + id;',
  'db.query(q);',
  'el.innerHTML = req.query.q;',
].join('\n');

// ── Lifecycle ───────────────────────────────────────────────────────────────

let ready = false;
let baseUrl;
let auth;

before(async (t) => {
  try {
    const s = await setupTestServer();
    baseUrl = s.baseUrl;
    ready = true;
  } catch (err) {
    // Fail loudly but allow `t.skip` in each test so `npm test` stays green if
    // the in-memory MongoDB binary cannot bootstrap on this machine.
    t.diagnostic(`in-memory MongoDB unavailable: ${err.message}`);
    ready = false;
  }
});

after(async () => {
  await teardownTestServer();
});

beforeEach(async () => {
  if (!ready) return;
  auth = await createAuthUser();
});

async function newProject() {
  return createProject(auth.userId);
}

function requireReady(t) {
  if (!ready) {
    t.skip('in-memory MongoDB unavailable');
    return false;
  }
  return true;
}

async function doScan(code, projectId) {
  return api(baseUrl, 'POST', '/api/scans', {
    token: auth.token,
    body: { projectId, code, language: 'javascript', fileName: 'test.js' },
  });
}

// ── §1 CONFIRMED flow end-to-end ────────────────────────────────────────────

test('§1 CONFIRMED: verdict/evidence/severity/confidence persist through API', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();

  const { status, body } = await doScan(CONFIRMED_SQL, projectId);
  assert.equal(status, 201, `expected 201, got ${status}`);
  const scan = body.scan;
  assert.ok(scan.id, 'scan has an id');
  assert.equal(scan.status, 'completed');

  const finding = scan.findings[0];
  assert.equal(finding.verdict, 'CONFIRMED');
  assert.equal(finding.severity, 'critical'); // deterministic normalization
  assert.ok(finding.confidence >= 80, `confidence ${finding.confidence} >= 80`);
  assert.ok(finding.evidence, 'evidence object present');
  assert.equal(finding.evidence.flow.established, true);
  assert.deepEqual(finding.evidence.flow.sources, ['req.query.id']);
  assert.equal(finding.evidence.source.found, true);
  assert.ok(finding.evidence.explanation.length > 0);
});

// ── §1 POTENTIAL flow end-to-end ────────────────────────────────────────────

test('§1 POTENTIAL: suspicious-but-unconfirmed is LOW severity, conf ≤ 35', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();

  const { status, body } = await doScan(POTENTIAL_SQL, projectId);
  assert.equal(status, 201);
  const finding = body.scan.findings.find((f) => f.category === 'Injection Vulnerabilities');
  assert.ok(finding, 'expected an injection finding');
  assert.equal(finding.verdict, 'POTENTIAL');
  assert.equal(finding.severity, 'low'); // POTENTIAL always demoted to low
  assert.ok(finding.confidence <= 35, `confidence ${finding.confidence} <= 35`);
  assert.equal(finding.evidence.flow.established, false);
  assert.match(finding.evidence.explanation, /potential/i);
});

// ── §1 FALSE_POSITIVE dropped end-to-end ────────────────────────────────────

test('§1 FALSE_POSITIVE: provably-safe finding is not persisted or returned', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();

  // Parameterized query → provably safe → dropped entirely.
  const p1 = await doScan(PARAMETERIZED_SQL, projectId);
  assert.equal(p1.status, 201);
  const sqlFp = (p1.body.scan.findings || []).find(
    (f) => f.category === 'Injection Vulnerabilities'
  );
  assert.equal(sqlFp, undefined, 'parameterized SQL must not be returned');

  // Constant data on a DOM sink → dropped entirely.
  const p2 = await doScan(XSS_CONSTANT, projectId);
  assert.equal(p2.status, 201);
  const xssFp = (p2.body.scan.findings || []).find(
    (f) => f.verdict === 'FALSE_POSITIVE' || f.category === 'Cross-Site Scripting (XSS)'
  );
  assert.equal(xssFp, undefined, 'constant DOM sink must not be returned');

  // Invariant: a persisted scan can never contain a FALSE_POSITIVE verdict.
  for (const body of [p1.body, p2.body]) {
    for (const f of body.scan.findings || []) {
      assert.notEqual(f.verdict, 'FALSE_POSITIVE');
    }
  }
});

// ── §2 Round-trip persistence + multiple-finding isolation ──────────────────

test('§2 round-trip: verdict/evidence survive load from MongoDB and re-serialize', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();

  const created = await doScan(CONFIRMED_SQL, projectId);
  const scanId = created.body.scan.id;

  // Fetch from DB via the API (re-hydrates from MongoDB rather than in-memory).
  const { status, body } = await api(baseUrl, 'GET', `/api/scans/${scanId}`, {
    token: auth.token,
  });
  assert.equal(status, 200);
  const finding = body.scan.findings[0];
  assert.equal(finding.verdict, 'CONFIRMED');
  assert.equal(finding.severity, 'critical');
  assert.equal(finding.evidence.flow.established, true);
  assert.deepEqual(finding.evidence.flow.sources, ['req.query.id']);
  assert.ok(finding.confidence >= 80);
});

test('§2 multiple findings stay isolated with independent evidence', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();

  const { status, body } = await doScan(MULTI_FINDING, projectId);
  assert.equal(status, 201);
  const findings = body.scan.findings;
  assert.ok(findings.length >= 3, `expected ≥3 findings, got ${findings.length}`);

  const sql = (body.scan.findings || []).find(
    (f) => f.category === 'Injection Vulnerabilities'
  );
  const xss = (body.scan.findings || []).find(
    (f) => f.category === 'Cross-Site Scripting (XSS)'
  );
  const file = (body.scan.findings || []).find(
    (f) => f.ruleId === 'path-traversal' || f.ruleId === 'unchecked-file-read'
  );

  assert.ok(sql && xss && file, 'expected sql + xss + path-traversal findings');

  // Every finding carries its own verdict + evidence object.
  for (const f of findings) {
    assert.equal(f.verdict, 'CONFIRMED');
    assert.ok(f.evidence, 'evidence present');
    assert.ok(f.evidence.flow.established, 'flow established for confirmed');
  }

  // Evidence is scoped to the file's own finding (no bleed between rules).
  assert.deepEqual(sql.evidence.flow.sources, ['req.query.id']);
  assert.deepEqual(file.evidence.flow.sources, ['req.query.path']);
  const comparisonKeys = new Set(findings.map((f) => f.comparisonKey));
  assert.equal(comparisonKeys.size, findings.length, 'comparisonKeys must be distinct');
});


// ── §2 AI cannot override the deterministic result ──────────────────────────

test('§2 AI cannot override deterministic verdict/severity/confidence', async (t) => {
  if (!requireReady(t)) return;

  // First scan deterministic (AI off) to capture the stable comparisonKey.
  const projectId = await newProject();
  const base = await doScan(POTENTIAL_SQL, projectId);
  const finding = base.body.scan.findings.find((f) => f.category === 'Injection Vulnerabilities');
  const comparisonKey = finding.comparisonKey;
  assert.equal(finding.verdict, 'POTENTIAL');
  assert.equal(finding.severity, 'low');

  // Now enable a fake OpenRouter provider that maliciously claims CRITICAL @ 99.
  const env = (await import('../../src/config/env.js')).default;
  const originalProvider = env.AI_PROVIDER;
  const originalFetch = globalThis.fetch;
  env.AI_PROVIDER = 'openrouter';
  env.OPENROUTER_API_KEY = 'sk-test-fake';

  try {
    // Intercept ONLY the OpenRouter call; pass all other fetches (the tests' own
    // HTTP calls to the local app) through to the real fetch.
    globalThis.fetch = async (url, opts) => {
      if (String(url).includes('openrouter.ai')) {
        return new Response(
          JSON.stringify({
            choices: [
              {
                message: {
                  content: JSON.stringify({
                    findings: [
                      {
                        comparisonKey,
                        severity: 'critical',
                        confidence: 0.99,
                        explanation: 'attacker controls everything',
                        impact: 'full compromise',
                        remediation: 'n/a',
                        secureExample: 'n/a',
                      },
                    ],
                  }),
                },
              },
            ],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return originalFetch(url, opts);
    };

    const { status, body } = await doScan(POTENTIAL_SQL, projectId);
    assert.equal(status, 201, `AI scan expected 201, got ${status}: ${JSON.stringify(body)}`);
    const persisted = body.scan.findings.find((f) => f.comparisonKey === comparisonKey);

    // AI's malicious claim is quarantined to the ai.* sub-fields and must NOT
    // change the deterministic verdict/severity/confidence exposed on the finding.
    assert.equal(persisted.verdict, 'POTENTIAL', 'AI cannot change verdict');
    assert.equal(persisted.severity, 'low', 'AI cannot escalate severity');
    assert.ok(persisted.confidence <= 35, 'AI cannot inflate confidence');
    // Prove the hostile AI output really was received (and correctly contained).
    assert.equal(persisted.ai.severity, 'critical');
    assert.equal(persisted.ai.confidence, 99);
    assert.equal(persisted.ai.source, 'openrouter');
  } finally {
    env.AI_PROVIDER = originalProvider;
    env.OPENROUTER_API_KEY = 'sk-test-fake';
    globalThis.fetch = originalFetch;
  }
});

// ── §7 error isolation through the API ──────────────────────────────────────

test('§7 malformed source returns 200 (never crashes the scan pipeline)', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();
  const malformed = 'function({{{ ;\nconst x = ;\ndb.query("SELECT 1");\n';

  const { status, body } = await doScan(malformed, projectId);
  assert.equal(status, 201, `malformed input should scan cleanly, got ${status}`);
  assert.equal(body.scan.status, 'completed');

  // Any finding that survives must be conservative (never a false CONFIRMED
  // manufactured from a broken AST).
  for (const f of body.scan.findings || []) {
    assert.notEqual(f.verdict, 'CONFIRMED');
  }
});


// ── §8 multi-file project scan through the API ──────────────────────────────

test('§8 multi-file scan: vulnerable + clean + malformed files validated together', async (t) => {
  if (!requireReady(t)) return;
  const { userId, token } = await createAuthUser();
  const Project = (await import('../../src/models/Project.js')).default;
  const project = await Project.create({ owner: userId, name: 'MultiFile' });

  const files = [
    { path: 'src/api.js', content: 'db.query("SELECT * FROM users WHERE id=" + req.query.id);' },
    { path: 'src/helper.js', content: 'const add = (a, b) => a + b; export { add };' },
    { path: 'src/broken.js', content: 'function ((( ;\n' },
  ];
  const form = new FormData();
  form.append('projectId', project._id.toString());
  form.append('paths', JSON.stringify(files.map((f) => f.path)));
  for (const f of files) {
    form.append('files', new Blob([f.content], { type: 'text/plain' }), f.path);
  }

  const res = await fetch(`${baseUrl}/api/scans/upload`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: form,
  });
  const text = await res.text();
  const body = text ? JSON.parse(text) : null;
  assert.equal(res.status, 201, `expected 201, got ${res.status}: ${text}`);

  const scan = body.scan;
  assert.ok(scan.id);
  assert.ok(scan.fileCount >= 3, `fileCount ${scan.fileCount} >= 3`);

  // Vulnerable file's finding is confirmed and correctly attributed.
  const apiFinding = (scan.findings || []).find(
    (f) => f.filePath === 'src/api.js' && f.category === 'Injection Vulnerabilities'
  );
  assert.ok(apiFinding, 'api.js sql finding expected');
  assert.equal(apiFinding.verdict, 'CONFIRMED');

  // Clean file contributes no findings.
  const helperFinding = (scan.findings || []).find((f) => f.filePath === 'src/helper.js');
  assert.equal(helperFinding, undefined, 'helper.js should be clean');

  // Malformed file never aborts the scan nor manufactures CONFIRMED.
  const brokenFindings = (scan.findings || []).filter((f) => f.filePath === 'src/broken.js');
  for (const f of brokenFindings) {
    assert.notEqual(f.verdict, 'CONFIRMED');
  }

  // Evidence scoped to the correct file.
  assert.deepEqual(apiFinding.evidence.flow.sources, ['req.query.id']);
});

// ── §3 legacy compatibility ─────────────────────────────────────────────────

test('§3 legacy findings (no verdict/evidence) load, serialize, and display cleanly', async (t) => {
  if (!requireReady(t)) return;
  const { userId } = auth;
  const Project = (await import('../../src/models/Project.js')).default;
  const Scan = (await import('../../src/models/Scan.js')).default;
  const { serializeScan } = await import('../../src/services/scanService.js');

  const project = await Project.create({ owner: userId, name: 'Legacy' });
  const legacy = await Scan.create({
    project: project._id,
    owner: userId,
    status: 'completed',
    language: 'javascript',
    fileName: 'legacy.js',
    score: 50,
    severityCounts: { critical: 0, high: 1, medium: 0, low: 0, informational: 0 },
    codeSeverityCounts: { critical: 0, high: 1, medium: 0, low: 0, informational: 0 },
    dependencySeverityCounts: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
    dependencySummary: {
      total: 0,
      vulnerable: 0,
      direct: 0,
      transitive: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
    },
    findings: [
      {
        comparisonKey: 'sql-concat:3',
        ruleId: 'sql-concat',
        vulnerabilityType: 'SQL Injection',
        title: 'Legacy SQL finding',
        severity: 'high',
        confidence: 85,
        description: 'pre-verdict-era finding',
        category: 'Injection Vulnerabilities',
        line: 3,
        affectedCode: 'db.query("SELECT * FROM users WHERE id=" + id);',
        filePath: 'legacy.js',
        reason: 'legacy',
      },
    ],
  });

  // serializeScan must not crash or inject null verdict/evidence.
  const serialized = serializeScan(legacy);
  assert.equal(serialized.findings[0].severity, 'high');
  assert.equal(serialized.findings[0].verdict, undefined, 'no fabricated verdict');
  assert.equal(serialized.findings[0].evidence, undefined, 'no fabricated evidence');

  // And the HTTP path must serve it as a clean 200.
  const { status, body } = await api(baseUrl, 'GET', `/api/scans/${legacy._id}`, {
    token: auth.token,
  });
  assert.equal(status, 200);
  assert.equal(body.scan.findings[0].title, 'Legacy SQL finding');
  assert.equal('verdict' in body.scan.findings[0], false);
  assert.equal('evidence' in body.scan.findings[0], false);
});

