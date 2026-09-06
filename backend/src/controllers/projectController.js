import Project from '../models/Project.js';
import Scan from '../models/Scan.js';
import { scoreLabel } from '../scanner/score.js';
import { compareScans } from '../services/rescanService.js';

/**
 * Project management controller (PHASES.md Phase 2).
 * All project data is isolated by owner; a user can only manage their own.
 */

export async function listProjects(req, res, next) {
  try {
    const projects = await Project.find({ owner: req.userId }).sort({ createdAt: -1 });
    // Attach a lightweight latest-scan summary for the dashboard.
    const result = [];
    for (const p of projects) {
      const latest = await Scan.findOne({ project: p._id, status: 'completed' })
        .sort({ createdAt: -1 })
        .select('score severityCounts createdAt')
        .exec();
      result.push({
        id: p._id,
        name: p.name,
        description: p.description,
        createdAt: p.createdAt,
        latestScan: latest
          ? {
              id: latest._id,
              score: latest.score,
              severityCounts: latest.severityCounts,
              createdAt: latest.createdAt,
            }
          : null,
      });
    }
    return res.json({ projects: result });
  } catch (err) {
    next(err);
  }
}

export async function createProject(req, res, next) {
  try {
    const { name, description } = req.body;
    const project = await Project.create({ owner: req.userId, name, description: description || '' });
    return res.status(201).json({ project });
  } catch (err) {
    next(err);
  }
}

export async function getProject(req, res, next) {
  try {
    const project = await Project.findOne({ _id: req.params.id, owner: req.userId });
    if (!project) return res.status(404).json({ error: 'Project not found' });
    return res.json({ project });
  } catch (err) {
    next(err);
  }
}

export async function updateProject(req, res, next) {
  try {
    const project = await Project.findOne({ _id: req.params.id, owner: req.userId });
    if (!project) return res.status(404).json({ error: 'Project not found' });
    if (req.body.name !== undefined) project.name = req.body.name;
    if (req.body.description !== undefined) project.description = req.body.description;
    await project.save();
    return res.json({ project });
  } catch (err) {
    next(err);
  }
}

export async function deleteProject(req, res, next) {
  try {
    const project = await Project.findOneAndDelete({ _id: req.params.id, owner: req.userId });
    if (!project) return res.status(404).json({ error: 'Project not found' });
    await Scan.deleteMany({ project: project._id });
    return res.json({ ok: true });
  } catch (err) {
    next(err);
  }
}

export async function getProjectOverview(req, res, next) {
  try {
    const project = await Project.findOne({ _id: req.params.id, owner: req.userId });
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const scans = await Scan.find({ project: project._id, status: 'completed' })
      .sort({ createdAt: -1 })
      .select('score severityCounts findings createdAt comparison')
      .exec();

    const latest = scans[0] || null;
    let comparisonSummary = null;
    if (latest && scans.length >= 2) {
      const prev = scans[1];
      const comparison = compareScans(prev, latest);
      comparisonSummary = {
        previousScore: prev.score,
        currentScore: latest.score,
        delta: latest.score - prev.score,
        resolved: comparison.resolved,
        remaining: comparison.remaining,
        new: comparison.new,
        previousScanId: prev._id,
        currentScanId: latest._id,
      };
    }

    const scanHistory = scans.map((s) => ({
      id: s._id,
      score: s.score,
      severityCounts: s.severityCounts,
      findingCount: s.findings ? s.findings.length : 0,
      createdAt: s.createdAt,
      hasComparison: !!(s.comparison && s.comparison.previousScore !== null && s.comparison.previousScore !== undefined),
    }));

    const aggregateSev = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    for (const s of scans) {
      for (const k of Object.keys(aggregateSev)) aggregateSev[k] += (s.severityCounts && s.severityCounts[k]) || 0;
    }

    return res.json({
      project,
      overallScore: latest ? latest.score : null,
      overallLabel: latest ? scoreLabel(latest.score) : null,
      severityCounts: latest ? latest.severityCounts : aggregateSev,
      latestScan: latest
        ? {
            id: latest._id,
            score: latest.score,
            severityCounts: latest.severityCounts,
            findingCount: latest.findings ? latest.findings.length : 0,
            createdAt: latest.createdAt,
          }
        : null,
      comparisonSummary,
      scanHistory,
    });
  } catch (err) {
    next(err);
  }
}
