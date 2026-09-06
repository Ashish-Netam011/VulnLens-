import { runScanner } from '../scanner/scanner.js';
import { calculateScore } from '../scanner/score.js';
import { analyzeWithAI } from '../ai/provider.js';
import { compareScans } from './rescanService.js';
import { parseDependencyManifests, isLockfilePath } from '../scanner/dependencyParser.js';
import { queryCVEs, buildDependencyFindings } from './cveLookup.js';
import Scan from '../models/Scan.js';

/**
 * Orchestrates the analysis pipeline: validate → run scanner → enrich with AI →
 * score → persist. Returns a complete Scan document.
 *
 * @param {object} params
 * @param {string} params.ownerId
 * @param {string} params.projectId
 * @param {string} params.code
 * @param {string} params.language
 * @param {string} params.fileName
 * @param {Array<{path: string, content: string}>} [params.files] - multi-file (project folder) scan
 */
export async function performScan({ ownerId, projectId, code, language = 'javascript', fileName = 'submission.txt', files = null }) {
  const multiFile = Array.isArray(files) && files.length > 0;

  // 1. Run deterministic rule-based scanner.
  let scanResult;
  let sourceCode;
  if (multiFile) {
    scanResult = runScanner(null, { files });
    // Lockfiles are parsed only by the dependency pipeline; exclude them from the
    // AI prompt so a huge generated lockfile never crowds out real source context.
    sourceCode = files
      .filter((f) => !isLockfilePath(f.path))
      .map((f) => `// ── ${f.path} ──\n${f.content}`)
      .join('\n\n');
    language = 'mixed';
    fileName = folderLabel(files);
  } else {
    scanResult = runScanner(code, { filePath: fileName });
    sourceCode = code;
  }
  let findings = scanResult.findings;
  const dependencySummary = emptyDependencySummary();

  // 1b. Dependency / CVE scan (Phase 2): parse manifests and query OSV.
  // Only meaningful for multi-file (project folder) scans where manifests are present.
  const depResult = multiFile ? parseDependencyManifests(files) : null;
  if (depResult && depResult.dependencies.length > 0) {
    try {
      const vulnMap = await queryCVEs(depResult.dependencies);
      const depFindings = [];
      for (const dep of depResult.dependencies) {
        const vulns = vulnMap.get(`${dep.name}@${dep.version}`) || [];
        depFindings.push(...buildDependencyFindings(dep, vulns, dep.sourceFile, depResult.manifestTypes?.[0]));
      }
      findings = [...findings, ...depFindings];
      computeDependencySummary(dependencySummary, depResult.dependencies, depFindings);
    } catch (err) {
      // Dependency scan must never fail the whole scan — log and continue with code results.
      console.error('Dependency/CVE scan errored:', err.message);
    }
  } else if (depResult) {
    // Manifests present but zero queryable deps — record zero summary.
    computeDependencySummary(dependencySummary, [], []);
  }

  // 2. Run AI analysis (best-effort; fall back to rule-authored enrichment).
  // Dependency findings are deterministic from OSV and skipped by the AI layer.
  let aiSource = 'rule';
  const aiResult = await analyzeWithAI({
    code: sourceCode,
    findings: findings.filter((f) => f.kind !== 'dependency'),
    projectName: 'scan',
    fileName,
  });

  if (aiResult.ok) {
    aiSource = aiResult.source;
    findings = findings.map((f) => {
      const enriched = aiResult.results.get(f.comparisonKey);
      const ruleEnrich = f._ruleEnrichment || {};
      // Dependency findings are deterministic from OSV, never AI-enriched.
      if (f.kind === 'dependency') {
        return {
          ...f,
          ai: {
            explanation: ruleEnrich.explanation || f.reason || '',
            impact: ruleEnrich.impact || '',
            remediation: ruleEnrich.remediation || '',
            secureExample: ruleEnrich.secureExample || '',
            severity: f.severity,
            confidence: f.confidence,
            source: 'osv',
          },
        };
      }
      if (enriched) {
        return {
          ...f,
          ai: {
            explanation: enriched.explanation || ruleEnrich.explanation || f.reason || '',
            impact: enriched.impact || ruleEnrich.impact || '',
            remediation: enriched.remediation || ruleEnrich.remediation || '',
            secureExample: enriched.secureExample || ruleEnrich.secureExample || '',
            severity: normalizeSeverityLike(enriched.severity) || f.severity,
            confidence: normalizedConfidence(enriched.confidence),
            source: aiSource,
          },
        };
      }
      // No AI result for this key -> use rule-authored enrichment.
      return {
        ...f,
        ai: {
          explanation: ruleEnrich.explanation || f.reason || '',
          impact: ruleEnrich.impact || '',
          remediation: ruleEnrich.remediation || '',
          secureExample: ruleEnrich.secureExample || '',
          severity: f.severity,
          confidence: f.confidence,
          source: 'rule',
        },
      };
    });
  } else {
    // AI disabled or failed: fill from rule-authored enrichment.
    findings = findings.map((f) => {
      const ruleEnrich = f._ruleEnrichment || {};
      return {
        ...f,
        ai: {
          explanation: ruleEnrich.explanation || f.reason || '',
          impact: ruleEnrich.impact || '',
          remediation: ruleEnrich.remediation || '',
          secureExample: ruleEnrich.secureExample || '',
          severity: f.severity,
          confidence: f.confidence,
          source: 'rule',
        },
      };
    });
  }

  // Remove hidden enrichment / internal helper fields before persisting.
  findings = findings.map(({ _ruleEnrichment, _ruleSeverity, ...rest }) => rest);

  // 3. Compute severity counts + score (independent of AI). severityCounts stays TOTAL
  // (code + dependency combined) so existing dashboard/list code is unaffected.
  const codeSeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  const dependencySeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const f of findings) {
    if (severityCounts[f.severity] !== undefined) severityCounts[f.severity]++;
  }
  for (const f of findings) {
    if (f.kind === 'dependency') {
      if (dependencySeverityCounts[f.severity] !== undefined) dependencySeverityCounts[f.severity]++;
    } else if (codeSeverityCounts[f.severity] !== undefined) {
      codeSeverityCounts[f.severity]++;
    }
  }
  const score = calculateScore(severityCounts, { findings });

  // 4. Persist scan and compute comparison with the previous scan of this project.
  const scan = await Scan.create({
    project: projectId,
    owner: ownerId,
    status: 'completed',
    sourceCode,
    sourceFiles: multiFile ? files.map((f) => ({ path: f.path, content: f.content })) : undefined,
    language,
    fileName,
    findings,
    score,
    severityCounts,
    codeSeverityCounts,
    dependencySeverityCounts,
    dependencySummary,
  });

  // 5. Compare with most recent previous scan.
  const previous = await Scan.findOne({ project: projectId, _id: { $ne: scan._id } }).sort({ createdAt: -1 });
  if (previous && previous.status === 'completed') {
    const comparison = compareScans(previous, scan);
    scan.comparisonVersion = (previous.comparisonVersion || 0) + 1;
    scan.comparison = {
      previousScanId: previous._id,
      previousScore: previous.score,
      resolved: comparison.resolved,
      remaining: comparison.remaining,
      new: comparison.new,
      delta: score - previous.score,
    };
    await scan.save();
  }

  return scan;
}

function normalizeSeverityLike(s) {
  const v = String(s || '').toLowerCase();
  if (['critical'].includes(v)) return 'critical';
  if (['high'].includes(v)) return 'high';
  if (['medium'].includes(v)) return 'medium';
  if (['low'].includes(v)) return 'low';
  return '';
}

function normalizedConfidence(c) {
  const n = Number(c);
  if (Number.isNaN(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n * 100)));
}

/**
 * Folder-scan label derived from the first uploaded file's relative path.
 * e.g. ["myapp/src/index.js", ...] -> "myapp/"
 */
function folderLabel(files) {
  const first = String(files[0]?.path || '').split('/')[0];
  return sanitizeLike(first || 'project') + '/';
}

function sanitizeLike(name) {
  return String(name || '')
    .split(/[\\/]/)
    .pop()
    .replace(/[\r\n<>:*?"|]/g, '_')
    .slice(0, 255) || 'project';
}

/**
 * Convert a Scan's findings into a serializable-safe shape for API responses.
 */
export function serializeScan(scan) {
  const doc = scan.toObject ? scan.toObject() : scan;
  return {
    id: doc._id,
    project: doc.project,
    status: doc.status,
    language: doc.language,
    fileName: doc.fileName,
    fileCount: Array.isArray(doc.sourceFiles) ? doc.sourceFiles.length : 0,
    findings: doc.findings,
    score: doc.score,
    severityCounts: doc.severityCounts,
    codeSeverityCounts: doc.codeSeverityCounts,
    dependencySeverityCounts: doc.dependencySeverityCounts,
    dependencySummary: doc.dependencySummary,
    comparisonVersion: doc.comparisonVersion,
    comparison: doc.comparison,
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
  };
}

export function emptyDependencySummary() {
  return { total: 0, vulnerable: 0, direct: 0, transitive: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 } };
}
export function computeDependencySummary(summary, deps, depFindings) {
  summary.total = deps.length;
  summary.direct = deps.filter((d) => d.type === 'direct').length;
  summary.transitive = deps.filter((d) => d.type === 'transitive').length;
  const byPackage = new Set();
  for (const f of depFindings) {
    if (!f.kind || f.kind === 'dependency') byPackage.add(`${f.packageName}@${f.installedVersion}`);
    if (summary.bySeverity[f.severity] !== undefined) summary.bySeverity[f.severity]++;
  }
  summary.vulnerable = byPackage.size;
  for (const key of Object.keys(summary.bySeverity)) {
    if (summary.bySeverity[key] === undefined) summary.bySeverity[key] = 0;
  }
}
