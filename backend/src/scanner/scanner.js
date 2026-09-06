import rules from './index.js';
import RULE_RICH_DATA from './ruleRichData.js';
import { buildEvidence } from './evidence.js';
import { determineVerdict } from './verdictEngine.js';
import { computeConfidence } from './confidenceEngine.js';
import { buildAnalysisSafe, serializeAnalysis, correlateFindingWithFunctionAnalysis } from './interproceduralEvidence.js';
import { integrateVerdict } from './verdictIntegration.js';

/**
 * Deterministic rule-based scanner (the "Finding Engine").
 * Runs every modular rule over the submitted source and normalizes findings
 * into a consistent schema, removing duplicates and generating stable IDs.
 */

function lineAt(code, index) {
  return code.slice(0, index).split('\n').length;
}

function getLineText(code, line) {
  const lines = code.split('\n');
  return lines[line - 1] ? lines[line - 1].trim().slice(0, 200) : '';
}

function hashCode(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash).toString(36);
}

/**
 * Scan source code and produce a normalized list of findings.
 * @param {string} code - submitted source code (ignored when opts.files is set)
 * @param {object} [opts]
 * @param {string} [opts.filePath]
 * @param {Array<{path: string, content: string}>} [opts.files] - multi-file/project mode
 * @returns {{findings: Array, severityCounts: object}}
 */
export function runScanner(code, opts = {}) {
  // Multi-file (project folder) mode: run the scanner over every file and merge
  // the results. File paths are embedded in comparisonKeys so findings from
  // different files never collide during rescan diffing.
  if (Array.isArray(opts.files) && opts.files.length > 0) {
    return runScannerOnFiles(opts.files);
  }

  const fileName = opts.filePath || 'submission.txt';

  const rawFindings = [];
  for (const rule of rules) {
    let results;
    try {
      results = rule.check(code) || [];
    } catch (err) {
      // A faulty rule must never break the whole scan.
      console.error(`Rule "${rule.id}" errored:`, err.message);
      results = [];
    }
    for (let f of results) {
      f.filePath = fileName;
      f.line = f.line || lineAt(code, 0);
      rawFindings.push(f);
    }
  }

  // Normalize + de-duplicate. A finding is a duplicate if the same rule fired
  // on the same line with the same ruleId.
  const seen = new Set();
  const findings = [];
  for (const f of rawFindings) {
    if (f.ruleId === 'no-helmet') continue; // too noisy/low-value heuristic
    const dedupeKey = `${f.ruleId}:${f.line}:${(f.affectedCode || '').slice(0, 40)}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    const normalized = {
      comparisonKey: `${f.ruleId}:${f.line}`,
      ruleId: f.ruleId,
      vulnerabilityType: f.vulnerabilityType || 'Finding',
      title: f.title || `${f.vulnerabilityType || 'Security'} Finding`,
      severity: normalizeSeverity(f.severity),
      confidence: clampConfidence(f.confidence),
      description: f.description || f.reason || '',
      category: f.category || 'General',
      line: f.line,
      affectedCode: f.affectedCode || getLineText(code, f.line),
      filePath: f.filePath,
      reason: f.reason || '',
    };
    // Attach rule-authored fallback enrichment (used by AI layer when offline)
    normalized._ruleEnrichment = enrichFromCategory(normalized.category, normalized);
    findings.push(normalized);
  }

  // Recompute comparison keys with a fingerprint for more robust rescan diffing.
  for (const f of findings) {
    f.comparisonKey = `${f.ruleId}:${f.line}:${hashCode(f.affectedCode || f.title)}`;
  }

  // Phase 4C: deterministic evidence → verdict → confidence → severity.
  // FALSE_POSITIVE findings are dropped; POTENTIAL are demoted to low severity.
  const processed = applyEvidenceEngine(code, findings);

  return {
    findings: processed,
    severityCounts: countSeverities(processed),
  };
}

/**
 * Phase 4C evidence engine.
 * For each finding: build AST evidence, derive a verdict, derive confidence,
 * and re-derive severity from the verdict. Drops FALSE_POSITIVE findings.
 * @param {string} code - single-file source the findings were produced from.
 * @param {Array} findings - normalized findings.
 * @returns {Array} processed findings (FALSE_POSITIVE removed).
 */
export function applyEvidenceEngine(code, findings) {
  const processed = [];
  // Lazily computed interprocedural analysis shared by Phase 5A metadata and
  // Phase 5B correlation. Computed once per file, AFTER verdict/confidence/
  // severity, so it can never influence them.
  let ipAnalysis = null;
  let ipMeta = null;

  for (const f of findings) {
    const evidence = buildEvidence(code, f);
    const verdict = determineVerdict(evidence, { category: f.category, ruleId: f.ruleId });

    if (verdict === 'FALSE_POSITIVE') continue; // drop provably-safe findings

    f.evidence = evidence;
    f.verdict = verdict;
    f.confidence = computeConfidence(evidence, verdict, f.confidence);
    f._ruleSeverity = f.severity; // save before deriveSeverity overwrites
    f.severity = deriveSeverity(verdict, f.severity);

    // Phase 5A + 5B: attach interprocedural STRUCTURAL metadata (function
    // summary + call graph) and its correlation. Purely descriptive — computed
    // AFTER verdict/confidence/severity so it can never influence them.
    if (ipAnalysis === null) {
      ipAnalysis = buildAnalysisSafe(code, f.filePath);
      ipMeta = serializeAnalysis(ipAnalysis);
    }
    if (ipMeta) {
      // Shallow clone per finding so each finding gets its own `correlation`;
      // nested 5A structures are never mutated and can be safely shared.
      f.evidence.interprocedural = { ...ipMeta };
      const correlation = correlateFindingWithFunctionAnalysis(f, ipAnalysis, { code });
      if (correlation) f.evidence.interprocedural.correlation = correlation;
    }

    // Phase 5E: controlled verdict integration (AFTER 5D calibration).
    // Reads calibration metadata and applies bounded adjustments to
    // confidence and/or verdict. Never touches ruleId, comparisonKey, score.
    integrateVerdict(f);

    processed.push(f);
  }
  return processed;
}

/**
 * Severity is always re-derived from the verdict, never copied from the rule.
 *   CONFIRMED -> keep rule severity
 *   LIKELY    -> cap at high
 *   POTENTIAL -> low
 */
function deriveSeverity(verdict, ruleSeverity) {
  if (verdict === 'CONFIRMED') return normalizeSeverity(ruleSeverity);
  if (verdict === 'LIKELY') {
    const s = normalizeSeverity(ruleSeverity);
    return s === 'critical' ? 'high' : s;
  }
  if (verdict === 'POTENTIAL') return 'low';
  return normalizeSeverity(ruleSeverity); // defensive; FALSE_POSITIVE is dropped earlier
}

/**
 * Multi-file (project folder) scanning.
 * Runs the rule engine over each file independently, then merges findings.
 * Each finding's comparisonKey is prefixed with its relative path so identical
 * snippets in different files are treated as distinct findings (and rescan
 * diffing stays accurate across files).
 */
function runScannerOnFiles(files) {
  const merged = [];
  for (const file of files) {
    const path = normalizeFilePath(file.path) || 'submission.txt';
    const content = file.content === undefined || file.content === null ? '' : String(file.content);
    const result = runScanner(content, { filePath: path });
    for (const f of result.findings) {
      f.comparisonKey = `${path}:${f.comparisonKey}`;
      merged.push(f);
    }
  }
  return {
    findings: merged,
    severityCounts: countSeverities(merged),
  };
}

function normalizeFilePath(p) {
  return String(p || '')
    .replace(/\\/g, '/')
    .replace(/^\/+/, '')
    .split('/')
    .filter((seg) => seg && seg !== '.' && seg !== '..')
    .join('/')
    .slice(0, 255);
}

function normalizeSeverity(s) {
  const v = String(s || '').toLowerCase();
  if (['critical'].includes(v)) return 'critical';
  if (['high', 'severe'].includes(v)) return 'high';
  if (['medium', 'moderate'].includes(v)) return 'medium';
  if (['low', 'minor'].includes(v)) return 'low';
  return 'informational';
}

function clampConfidence(c) {
  const n = Number(c);
  if (Number.isNaN(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}

function enrichFromCategory(category, finding) {
  const data = RULE_RICH_DATA[category];
  if (!data) {
    return {
      explanation:
        `This rule (${finding.ruleId}) detected a potential security issue in the submitted code. Review the affected line and confirm whether the pattern is reachable by untrusted input.`,
      impact:
        'Depending on context, this pattern may allow an attacker to compromise confidentiality, integrity, or availability of the application or its data.',
      remediation:
        'Review the flagged code, apply the relevant secure-coding guidance for the vulnerability type, and verify the fix via a rescan.',
      secureExample: '// Apply secure-coding best practices for the detected pattern.',
    };
  }
  return data;
}

function countSeverities(findings) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity]++;
  }
  return counts;
}

export function countSeveritiesPublic(findings) {
  return countSeverities(findings);
}
