import Project from '../models/Project.js';
import Scan from '../models/Scan.js';
import { scoreLabel } from '../scanner/score.js';

/**
 * Global security dashboard (PHASES.md Phase 8).
 * Aggregates across all projects owned by the authenticated user.
 */
export async function getDashboard(req, res, next) {
  try {
    const projects = await Project.find({ owner: req.userId }).sort({ createdAt: -1 });
    const projectIds = projects.map((p) => p._id);

    const scans = projectIds.length
      ? await Scan.find({ project: { $in: projectIds }, status: 'completed' })
          .sort({ createdAt: -1 })
          .select('project score severityCounts findings createdAt createdAt comparison')
          .exec()
      : [];

    // Most recent scan per project.
    const latestPerProject = new Map();
    for (const s of scans) {
      if (!latestPerProject.has(String(s.project))) latestPerProject.set(String(s.project), s);
    }
    const latestScans = [...latestPerProject.values()];

    // Severity distribution across the most recent scans.
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    let totalFindings = 0;
    for (const s of latestScans) {
      for (const k of Object.keys(severityCounts)) {
        severityCounts[k] += (s.severityCounts && s.severityCounts[k]) || 0;
      }
      totalFindings += s.findings ? s.findings.length : 0;
    }

    const latestScan = latestScans[0] || null;
    const overallScore = latestScans.length
      ? Math.round(latestScans.reduce((a, s) => a + s.score, 0) / latestScans.length)
      : null;

    const recentScans = scans.slice(0, 8).map((s) => ({
      id: s._id,
      project: s.project,
      score: s.score,
      severityCounts: s.severityCounts,
      findingCount: s.findings ? s.findings.length : 0,
      createdAt: s.createdAt,
    }));

    const categoryDistribution = {};
    for (const s of latestScans) {
      for (const f of s.findings || []) {
        categoryDistribution[f.category || 'Other'] = (categoryDistribution[f.category || 'Other'] || 0) + 1;
      }
    }

    // Score progression: latest scan per project over time.
    const progression = latestScans
      .map((s) => ({ date: s.createdAt, score: s.score, projectId: s.project }))
      .sort((a, b) => new Date(a.date) - new Date(b.date));

    return res.json({
      projectCount: projects.length,
      scanCount: scans.length,
      overallScore,
      overallLabel: overallScore === null ? null : scoreLabel(overallScore),
      severityCounts,
      totalFindings,
      latestProject: latestScan && projects.find((p) => String(p._id) === String(latestScan.project))
        ? {
            id: latestScan.project,
            name: (projects.find((p) => String(p._id) === String(latestScan.project)) || {}).name,
            score: latestScan.score,
          }
        : null,
      recentScans,
      categoryDistribution,
      progression,
    });
  } catch (err) {
    next(err);
  }
}
