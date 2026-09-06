import Project from '../models/Project.js';
import Scan from '../models/Scan.js';
import { scoreLabel } from '../scanner/score.js';
import { buildComparisonDetail } from './rescanService.js';

/**
 * Report generation service (PHASES.md Phase 10).
 * Builds a structured, read-only security report that does not expose secrets
 * (sensitive values are masked upstream by the scanner).
 */

export async function generateReport(scanId, ownerId) {
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

  const project = await Project.findById(scan.project).exec();

  const label = scoreLabel(scan.score);

  // Comparison detail against the immediately previous scan, if any.
  let comparison = null;
  if (scan.comparison && scan.comparison.previousScore !== null && scan.comparison.previousScore !== undefined) {
    const previous = await Scan.findById(scan.comparison.previousScanId).exec().catch(() => null);
    comparison = {
      previousScore: scan.comparison.previousScore,
      currentScore: scan.score,
      delta: scan.comparison.delta,
      resolved: scan.comparison.resolved,
      remaining: scan.comparison.remaining,
      new: scan.comparison.new,
      detail: previous ? buildComparisonDetail(previous, scan) : null,
    };
  }

  const report = {
    generatedAt: new Date().toISOString(),
    project: {
      id: project ? project._id : scan.project,
      name: project ? project.name : 'Untitled Project',
      description: project ? project.description : '',
    },
    scan: {
      id: scan._id,
      createdAt: scan.createdAt,
      language: scan.language,
      fileName: scan.fileName,
      fileCount: Array.isArray(scan.sourceFiles) ? scan.sourceFiles.length : 0,
      files: Array.isArray(scan.sourceFiles) ? scan.sourceFiles.map((f) => f.path) : undefined,
      status: scan.status,
    },
    securityScore: {
      value: scan.score,
      label: label.label,
      outOf: 100,
    },
    severitySummary: scan.severityCounts,
    codeSeverityCounts: scan.codeSeverityCounts,
    dependencySeverityCounts: scan.dependencySeverityCounts,
    dependencySummary: scan.dependencySummary || null,
    findingCount: scan.findings ? scan.findings.length : 0,
    findings: (scan.findings || []).map((f) => ({
      title: f.title,
      vulnerabilityType: f.vulnerabilityType,
      severity: f.severity,
      confidence: f.confidence,
      category: f.category,
      kind: f.kind,
      line: f.line,
      filePath: f.filePath,
      packageName: f.packageName,
      installedVersion: f.installedVersion,
      cveId: f.cveId,
      recommendedVersion: f.recommendedVersion,
      affectedVersionRange: f.affectedVersionRange,
      dependencyType: f.dependencyType,
      advisoryUrl: f.advisoryUrl,
      sourceFile: f.sourceFile,
      affectedCode: f.affectedCode,
      reason: f.reason || undefined,
      ai: f.ai
        ? {
            explanation: f.ai.explanation,
            impact: f.ai.impact,
            remediation: f.ai.remediation,
            secureExample: f.ai.secureExample,
            source: f.ai.source,
          }
        : undefined,
    })),
    comparisonSummary: comparison
      ? {
          previousScore: comparison.previousScore,
          currentScore: comparison.currentScore,
          delta: comparison.delta,
          resolved: comparison.resolved,
          remaining: comparison.remaining,
          new: comparison.new,
        }
      : null,
  };

  return report;
}

export default { generateReport };
