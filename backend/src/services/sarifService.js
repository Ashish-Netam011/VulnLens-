import { createHash } from 'node:crypto';
import Scan from '../models/Scan.js';

/**
 * SARIF 2.1.0 report generation service (Phase 3).
 *
 * This service is purely a REPORTING layer: it consumes the exact same
 * deterministic findings used by JSON reports, the dashboard, and rescan
 * verification. It does NOT run a second scanner and does NOT re-evaluate
 * severity — SARIF `level` is derived solely from the existing deterministic
 * finding severity via a fixed mapping.
 *
 * Design guarantees maintained from the rest of VulnLens:
 *  - ownership isolation (User A can never read User B's SARIF report)
 *  - secret masking (raw secret values are never embedded)
 *  - path sanitization (no server absolute / drive / user paths)
 *  - stable identity (fingerprints derive from the comparisonKey)
 */

export const SARIF_VERSION = '2.1.0';
export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
export const TOOL_NAME = 'VulnLens';
export const TOOL_VERSION = '1.3.0';

/**
 * Deterministic VulnLens severity -> SARIF level mapping.
 * Never influenced by AI; unknown severities fall back to `note`.
 */
export function severityToSarifLevel(severity) {
  switch (String(severity || '').toLowerCase()) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
    case 'informational':
    default:
      return 'note';
  }
}

/**
 * Normalize a finding file path into a safe, portable SARIF artifact URI.
 * - collapses Windows backslashes to '/'
 * - strips drive letters (C:), UNC prefixes, and leading slashes
 * - drops traversal segments (..) and current dir segments (.)
 * - collapses duplicate slashes and trims trailing slashes
 * - limits to 255 chars
 *
 * Never returns server-absolute, user, or environment-bound paths.
 * Returns '' when there is nothing safe to emit.
 */
export function normalizeSarifPath(filePath) {
  if (filePath === null || filePath === undefined) return '';
  let p = String(filePath).trim();
  if (!p) return '';

  // Character-encode URI-unsafe characters so the value is a valid relative URI.
  const encode = (s) =>
    s.replace(/[^A-Za-z0-9\-._~!$&'()*+,;=:@\/%]/g, (c) =>
      encodeURIComponent(c)
    );

  // Remove Windows drive/UNC prefixes and leading slashes.
  p = p.replace(/^[A-Za-z]:/, '').replace(/^\/\/[^/]+\/[^/]+/, '');
  p = p.replace(/\\/g, '/');
  p = p.replace(/\/+/g, '/');
  p = p.replace(/^\/+/, '');
  p = p.replace(/\/+$/, '');

  const segments = p
    .split('/')
    .filter((seg) => seg && seg !== '.' && seg !== '..')
    .slice(0, 40);

  if (segments.length === 0) return '';

  // Strip a leading homedir marker plus its username component pair
  // (Windows "Users/<name>", Unix "home/<name>", legacy "Documents and
  // Settings/<name>") so personal usernames never leak into SARIF.
  if (
    (segments[0] === 'Users' || segments[0] === 'home' || segments[0] === 'Documents and Settings') &&
    segments.length >= 2
  ) {
    segments.splice(0, 2);
  }

  if (segments.length === 0) return '';

  let out = segments.join('/');
  if (out.length > 255) out = out.slice(0, 255);
  return encode(out);
}

/**
 * Deterministic SHA-256 hex fingerprint from the finding comparisonKey.
 * ComparisonKeys are already path-namespaced for folder scans, so identical
 * snippets in different files produce distinct fingerprints. Truncated to keep
 * SARIF payloads lean while remaining collision-resistant in practice.
 */
export function fingerprintFor(finding) {
  const seed = finding && typeof finding.comparisonKey === 'string' && finding.comparisonKey
    ? finding.comparisonKey
    : `${finding && finding.ruleId ? finding.ruleId : 'finding'}`;
  return createHash('sha256').update(seed).digest('hex').slice(0, 32);
}

/**
 * Safe, secret-free descriptive text for a finding/rule.
 * affectedCode is deliberately excluded — it can contain (masked) secret
 * patterns and is never emitted into SARIF.
 */
function safeText(finding, field) {
  const v = finding && finding[field];
  if (typeof v === 'string' && v.trim()) return v.trim();
  return '';
}

/**
 * Build a stable driver rule entry from a finding, deduplicated by ruleId.
 * Descriptions never embed raw secrets (title / category / reason are safe;
 * affectedCode is excluded).
 */
export function buildRule(finding) {
  const level = severityToSarifLevel(
    finding && finding.severity ? finding.severity : 'informational'
  );
  const rule = {
    id: String((finding && finding.ruleId) || 'unknown-rule'),
    name: safeText(finding, 'vulnerabilityType') || 'Security Finding',
    shortDescription: {
      text: safeText(finding, 'title') || 'Security Finding',
    },
    defaultConfiguration: { level },
  };
  const full = safeText(finding, 'description');
  const help = safeText(finding, 'reason');
  if (full) rule.fullDescription = { text: full };
  if (help) rule.help = { text: help };
  return rule;
}

/**
 * Build the set of driver.rules, deduplicated by ruleId. First occurrence wins
 * so output is deterministic regardless of finding order variants.
 */
export function buildRules(findings) {
  const byId = new Map();
  for (const f of findings || []) {
    const id = String((f && f.ruleId) || 'unknown-rule');
    if (byId.has(id)) continue;
    byId.set(id, buildRule(f));
  }
  return [...byId.values()];
}

/**
 * Convert a single VulnLens finding into a SARIF result.
 */
export function buildResult(finding) {
  const f = finding || {};
  const result = {
    ruleId: String(f.ruleId || 'unknown-rule'),
    level: severityToSarifLevel(f.severity),
    message: {
      text: safeText(f, 'title') || 'Security finding',
    },
  };

  const props = {};
  const kind = f.kind === 'dependency' ? 'dependency' : 'code';
  props.kind = kind;

  // Phase 6D: baseline regression status (NEW / BASELINED) is additive
  // metadata in the SARIF property bag; baselined findings are never removed
  // from the report, only their CI-gating behavior changes.
  if (f.baselineStatus) props.baselineStatus = f.baselineStatus;
  if (f.baselineEscalated) props.baselineEscalated = true;

  // Dependency findings carry rich, useful CVE/advisory metadata.
  if (kind === 'dependency') {
    if (f.packageName) props.packageName = f.packageName;
    if (f.installedVersion) props.installedVersion = f.installedVersion;
    if (f.dependencyType) props.dependencyType = f.dependencyType;
    if (f.cveId) props.cve = f.cveId;
    if (f.affectedVersionRange) props.affectedRange = f.affectedVersionRange;
    if (f.recommendedVersion) props.fixedVersion = f.recommendedVersion;
    if (f.advisoryUrl) props.advisoryUrl = f.advisoryUrl;
  } else {
    if (f.vulnerabilityType) props.vulnerabilityType = f.vulnerabilityType;
    if (f.category) props.category = f.category;
    if (f.confidence !== undefined && f.confidence !== null && f.confidence !== '') {
      props.confidence = f.confidence;
    }
  }
  if (Object.keys(props).length > 0) result.properties = props;

  // Attach a physical location when we have a usable artifact path.
  const uri = normalizeSarifPath(f.filePath);
  if (uri) {
    const physicalLocation = {
      artifactLocation: { uri },
    };
    const line = Number(f.line);
    if (Number.isInteger(line) && line > 0) {
      const region = { startLine: line };
      const column = Number(f.column);
      if (Number.isInteger(column) && column > 0) region.startColumn = column;
      const endLine = Number(f.endLine);
      if (Number.isInteger(endLine) && endLine >= line) region.endLine = endLine;
      physicalLocation.region = region;
    }
    result.locations = [{ physicalLocation }];
  }

  result.partialFingerprints = {
    primaryLocationLineHash: fingerprintFor(f),
  };

  return result;
}

/**
 * Build a complete SARIF 2.1.0 document from a scan's findings.
 * Pure and DB-free; works for single-file, folder, code-only, dependency-only,
 * mixed, and empty scans.
 */
export function buildSarifReport(scan) {
  const findings = Array.isArray(scan && scan.findings) ? scan.findings : [];
  const results = findings.map(buildResult);
  const rules = buildRules(findings);

  const driver = {
    name: TOOL_NAME,
    version: TOOL_VERSION,
    semanticVersion: TOOL_VERSION,
  };
  if (rules.length > 0) driver.rules = rules;

  return {
    version: SARIF_VERSION,
    $schema: SARIF_SCHEMA,
    runs: [
      {
        tool: { driver },
        results,
      },
    ],
  };
}

/**
 * Serialize a SARIF document to pretty JSON. Exported so callers and tests can
 * inspect the exact wire format.
 */
export function serializeSarif(sarif) {
  return JSON.stringify(sarif, null, 2);
}

/**
 * DB-aware generation with the exact same authorization semantics as
 * `generateReport`: 404 when the scan does not exist, 403 when the requesting
 * user is not the scan owner. Never leaks internal filesystem or stack data.
 */
export async function generateSarif(scanId, ownerId) {
  const scan = await Scan.findById(scanId).exec();
  if (!scan) {
    const err = new Error('Scan not found');
    err.status = 404;
    throw err;
  }
  if (String(scan.owner) !== String(ownerId)) {
    const err = new Error('Not authorized to access this scan');
    err.status = 403;
    throw err;
  }
  return buildSarifReport(scan);
}

export default { buildSarifReport, generateSarif, severityToSarifLevel, normalizeSarifPath };
