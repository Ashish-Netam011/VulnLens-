/**
 * OSV.dev CVE lookup service (Phase 2).
 * Queries OSV's /v1/querybatch for an npm package@version and merges results
 * into deterministic dependency findings.
 *
 * Design notes:
 *  - SSRF-safe: the endpoint URL comes only from env (OSV_API_URL), never from
 *    user input, so a crafted package name cannot redirect our request.
 *  - The npm ecosystem lookup filters by exact version server-side, so we never
 *    do our own range math for the installed version.
 *  - Results are cached in-memory (TTL) keyed by name@version.
 */
import env from '../config/env.js';

const OSV_API_URL = env.OSV_API_URL || 'https://api.osv.dev/v1/querybatch';
const CACHE_TTL_MS = env.CVE_LOOKUP_CACHE_TTL_MS || 6 * 60 * 60 * 1000;
const TIMEOUT_MS = env.CVE_LOOKUP_TIMEOUT_MS || 12000;
const BATCH_SIZE = 1000;
const MAX_VERSIONS_PER_QUERY = 256;

const cache = new Map(); // key name@version -> {ts, vulnerabilities[]}

function cacheKey(name, version) { return `${name}@${version}`; }
function pruneCache() {
  const now = Date.now();
  for (const [k, v] of cache) { if (now - v.ts > CACHE_TTL_MS) cache.delete(k); }
}
export function clearCache() { cache.clear(); }

export function buildBatchQuery(deps, { batchSize = BATCH_SIZE } = {}) {
  const chunks = [];
  for (let i = 0; i < deps.length; i += batchSize) {
    const slice = deps.slice(i, i + batchSize);
    const queries = [];
    for (const d of slice) {
      if (!d || !d.name || !d.version) continue;
      queries.push({ package: { ecosystem: 'npm', name: d.name }, version: d.version });
    }
    chunks.push({ queries });
  }
  return chunks;
}

export function mapSeverity(input) {
  const v = String(input || '').toLowerCase();
  if (v.includes('critical') || /^(9|10)(\.\d)?$/.test(v)) return 'critical';
  if (v.includes('high')) return 'high';
  if (v.includes('medium') || v.includes('moderate')) return 'medium';
  if (v.includes('low')) return 'low';
  return 'informational';
}

export function extractCvssScore(impact) {
  if (!impact || typeof impact !== 'object') return null;
  for (const key of ['cvss_v4', 'cvss_v3', 'cvss_v2']) {
    const cvss = impact[key];
    if (!cvss) continue;
    const score = cvss.baseScore ?? cvss.score;
    const n = Number(score);
    if (!Number.isNaN(n) && n >= 0) return n;
  }
  const s = impact.cvss_v3_1?.baseScore ?? impact.cvss_v3?.baseScore;
  const m = Number(s);
  if (!Number.isNaN(m)) return m;
  return null;
}
function severityFromNumber(score) {
  if (score == null) return 'informational';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score >= 0.1) return 'low';
  return 'informational';
}
export function resolveAdvisorySeverity(entries) {
  let best = 'informational';
  const order = { informational: 0, low: 1, medium: 2, high: 3, critical: 4 };
  function consider(s) {
    const mapped = mapSeverity(s);
    if (order[mapped] > order[best]) best = mapped;
  }
  for (const e of entries || []) {
    for (const impact of e.impact || []) {
      const score = extractCvssScore(impact);
      consider(impact.severity ?? severityFromNumber(score));
    }
  }
  return best;
}
export function extractRecommendedVersion(affected) {
  if (!Array.isArray(affected)) return null;
  let best = null;
  for (const a of affected) {
    for (const r of a.ranges || []) {
      for (const ev of r.events || []) {
        if (ev.fixed) { if (!best || compareSemver(ev.fixed, best) > 0) best = ev.fixed; }
      }
    }
  }
  return best;
}
export function compareSemver(a, b) {
  const pa = parseSemver(a); const pb = parseSemver(b);
  if (!pa || !pb) return String(a).localeCompare(String(b));
  if (pa[0] !== pb[0]) return pa[0] - pb[0];
  if (pa[1] !== pb[1]) return pa[1] - pb[1];
  if (pa[2] !== pb[2]) return pa[2] - pb[2];
  if (pa[3] !== pb[3]) return pa[3] ? -1 : 1;
  return 0;
}
function parseSemver(v) {
  const m = String(v || '').trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:-(.*))?$/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3]), m[4] || null];
}
export function buildAdvisoryUrl(advisory) {
  const ds = advisory.database_specific || {};
  const candidates = [ds.advisory, ds.url, ds.advisory_url, ds.osvdb_fd, ds.guestbook_url];
  for (const c of candidates) {
    if (typeof c === 'string' && /^https?:\/\//i.test(c) && c.length < 2048) return c;
  }
  const id = advisory.id ? encodeURIComponent(advisory.id) : 'vulnerability';
  return `${OSV_API_URL.replace(/\/v1\/?.*$/, '').replace(/\/$/, '')}/vulnerability/${id}`;
}
function chunkArray(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

export async function queryCVEs(deps, opts = {}) {
  const results = new Map();
  if (!Array.isArray(deps) || deps.length === 0) return results;
  const unique = [];
  const seen = new Set();
  for (const d of deps) {
    if (!d || !d.name || !d.version) continue;
    const key = cacheKey(d.name, d.version);
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push({ name: d.name, version: d.version });
  }
  const toFetch = [];
  for (const u of unique) {
    const key = cacheKey(u.name, u.version);
    const hit = cache.get(key);
    if (hit) results.set(key, hit.vulnerabilities);
    else toFetch.push(u);
  }
  for (const chunk of chunkArray(toFetch, BATCH_SIZE)) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? TIMEOUT_MS);
    const fetcher = opts.fetch || globalThis.fetch;
    const body = { queries: chunk.map((u) => ({ package: { ecosystem: 'npm', name: u.name }, version: u.version })) };
    try {
      const res = await fetcher(OSV_API_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: opts.signal || controller.signal,
      });
      if (!res || typeof res.json !== 'function') throw new Error('OSV returned an invalid response');
      if (res.status === 429) throw new Error('OSV rate limit exceeded');
      if (!res.ok) throw new Error(`OSV returned HTTP ${res.status}`);
      const data = await res.json();
      const rows = Array.isArray(data?.results) ? data.results : [];
      for (let i = 0; i < chunk.length && i < rows.length; i++) {
        const vulns = Array.isArray(rows[i]?.vulns) ? rows[i].vulns : [];
        const key = cacheKey(chunk[i].name, chunk[i].version);
        cache.set(key, { ts: Date.now(), vulnerabilities: vulns });
        results.set(key, vulns);
      }
    } finally {
      clearTimeout(timer);
    }
  }
  return results;
}

export function buildDependencyFindings(dep, vulnerabilities, sourceFile, manifestType) {
  const findings = [];
  for (const v of vulnerabilities || []) {
    if (!v || !v.id) continue;
    const severity = resolveAdvisorySeverity(v.affected);
    const fixed = extractRecommendedVersion(Array.isArray(v.affected) ? v.affected : null);
    findings.push({
      comparisonKey: `dep:${dep.name}@${dep.version}:${v.id}`,
      kind: 'dependency',
      ruleId: 'osv-advisory',
      dependencyType: dep.type || 'transitive',
      packageName: dep.name,
      installedVersion: dep.version,
      recommendedVersion: fixed || '',
      cveId: v.id,
      affectedVersionRange: describeAffectedRanges(v.affected),
      advisoryUrl: buildAdvisoryUrl(v),
      severity,
      confidence: 90,
      vulnerabilityType: 'Dependency Vulnerability',
      title: `${dep.name} — ${v.id}`,
      category: 'Dependencies',
      description: v.summary || v.details || `${dep.name}@${dep.version} is affected by ${v.id}.`,
      affectedCode: '',
      filePath: sourceFile || '',
      line: 0,
      reason: `Package ${dep.name} (installed ${dep.version}) is flagged by ${v.id}.`,
      _ruleEnrichment: {
        explanation: v.summary || v.details || `OSV tracks ${v.id} as affecting ${dep.name}.`,
        impact: severity === 'critical' || severity === 'high'
          ? 'This known vulnerability can compromise the application; upgrade the package to a patched version.'
          : 'Using an affected dependency version can expose the application to a known, but lower-rated, vulnerability.',
        remediation: fixed
          ? `Upgrade ${dep.name} to ${fixed} or a later patched version and re-run the scan.`
          : `Upgrade ${dep.name} to the latest patched version and re-run the scan.`,
        secureExample: `"${dep.name}": "${fixed || '>=<patched-version>'}"`,
      },
    });
  }
  return findings;
}

function describeAffectedRanges(affected) {
  if (!Array.isArray(affected)) return '';
  const parts = [];
  for (const a of affected) {
    if (typeof a === 'string') { parts.push(a); continue; }
    for (const r of a.ranges || []) {
      const evs = (r.events || []).map((e) => {
        if (e.introduced) return `>=${e.introduced}`;
        if (e.fixed) return `<${e.fixed}`;
        if (e.last_affected) return `<=${e.last_affected}`;
        return '';
      }).filter(Boolean);
      if (evs.length) parts.push(evs.join(' '));
    }
    for (const r of a.versions || []) parts.push(r);
  }
  return [...new Set(parts.filter(Boolean))].slice(0, 4).join(' | ');
}

export const _test = { OSV_API_URL, CACHE_TTL_MS, TIMEOUT_MS, BATCH_SIZE, MAX_VERSIONS_PER_QUERY, cache, buildBatchQuery };

