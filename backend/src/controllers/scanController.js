import Project from '../models/Project.js';
import Scan from '../models/Scan.js';
import { performScan, serializeScan } from '../services/scanService.js';
import { buildComparisonDetail } from '../services/rescanService.js';
import { normalizeLanguage, allowedExtension, sanitizeRelativePath, sanitizeFileName } from '../utils/validation.js';

/**
 * Scan controller (PHASES.md Phase 3, 9).
 * Ownership is always enforced against req.userId.
 */

// Limits for multi-file (project folder) uploads.
const MAX_UPLOAD_FILES = 100;
const MAX_TOTAL_CHARS = 5_000_000;

export async function listScans(req, res, next) {
  try {
    const { projectId } = req.query;
    const filter = { owner: req.userId };
    if (projectId) filter.project = projectId;
    const scans = await Scan.find(filter)
      .sort({ createdAt: -1 })
      .select('project score severityCounts codeSeverityCounts dependencySeverityCounts dependencySummary status fileName language createdAt comparison findings sourceFiles.path')
      .exec();
    const result = scans.map((s) => ({
      id: s._id,
      project: s.project,
      status: s.status,
      score: s.score,
      severityCounts: s.severityCounts,
      codeSeverityCounts: s.codeSeverityCounts,
      dependencySeverityCounts: s.dependencySeverityCounts,
      dependencySummary: s.dependencySummary,
      fileName: s.fileName,
      language: s.language,
      fileCount: Array.isArray(s.sourceFiles) ? s.sourceFiles.length : 0,
      findingCount: s.findings ? s.findings.length : 0,
      hasComparison: !!(s.comparison && s.comparison.previousScore !== null && s.comparison.previousScore !== undefined),
      comparison: s.comparison,
      createdAt: s.createdAt,
    }));
    return res.json({ scans: result });
  } catch (err) {
    next(err);
  }
}

export async function createScan(req, res, next) {
  try {
    const { projectId, code, language, fileName } = req.body;

    const project = await Project.findOne({ _id: projectId, owner: req.userId });
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const scan = await performScan({
      ownerId: req.userId,
      projectId,
      code,
      language: normalizeLanguage(language),
      fileName: sanitizeFileName(fileName),
    });

    return res.status(201).json({ scan: serializeScan(scan) });
  } catch (err) {
    next(err);
  }
}

/**
 * Multi-file (project folder) scan upload.
 * Accepts multipart/form-data:
 *   - "projectId"  : text field, id of the owning project
 *   - "paths"      : JSON array of relative file paths, aligned with "files"
 *   - "files"      : one or more file parts (order matches "paths")
 */
export async function uploadScan(req, res, next) {
  try {
    const { projectId } = req.body || {};
    if (!projectId || typeof projectId !== 'string') {
      return res.status(400).json({ error: 'projectId is required' });
    }

    const project = await Project.findOne({ _id: projectId, owner: req.userId });
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const uploaded = Array.isArray(req.files) ? req.files : [];
    if (uploaded.length === 0) {
      return res.status(400).json({ error: 'No files received. Choose a project folder to upload.' });
    }
    if (uploaded.length > MAX_UPLOAD_FILES) {
      return res.status(400).json({ error: `Too many files (max ${MAX_UPLOAD_FILES})` });
    }

    // Paths arrive as a JSON-encoded array aligned by index with req.files.
    let rawPaths = req.body.paths;
    if (typeof rawPaths === 'string') {
      try {
        rawPaths = JSON.parse(rawPaths);
      } catch {
        return res.status(400).json({ error: 'Invalid paths payload' });
      }
    }
    if (!Array.isArray(rawPaths)) {
      return res.status(400).json({ error: 'paths must be a JSON array aligned with files' });
    }

    // Pair files with their relative paths, dropping unsupported entries.
    const files = [];
    for (let i = 0; i < uploaded.length; i++) {
      const relPath = sanitizeRelativePath(rawPaths[i]);
      if (!relPath || !allowedExtension(relPath)) continue;
      files.push({
        path: relPath,
        content: uploaded[i].buffer ? uploaded[i].buffer.toString('utf8') : '',
      });
    }

    if (files.length === 0) {
      return res.status(400).json({ error: 'No supported code files found in the uploaded folder' });
    }

    const totalChars = files.reduce((sum, f) => sum + f.content.length, 0);
    if (totalChars > MAX_TOTAL_CHARS) {
      return res.status(400).json({ error: 'Total code size is too large (max 5,000,000 characters)' });
    }

    const scan = await performScan({
      ownerId: req.userId,
      projectId,
      files,
    });

    return res.status(201).json({ scan: serializeScan(scan) });
  } catch (err) {
    next(err);
  }
}

export async function getScan(req, res, next) {
  try {
    const scan = await Scan.findOne({ _id: req.params.id, owner: req.userId });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    return res.json({ scan: serializeScan(scan) });
  } catch (err) {
    next(err);
  }
}

export async function getScanComparison(req, res, next) {
  try {
    const scan = await Scan.findOne({ _id: req.params.id, owner: req.userId });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    const previous = scan.comparison && scan.comparison.previousScanId
      ? await Scan.findById(scan.comparison.previousScanId).select('score findings createdAt').exec()
      : null;

    if (!previous) {
      return res.json({ comparison: null, detail: null });
    }

    const detail = buildComparisonDetail(previous, scan);
    return res.json({
      comparison: scan.comparison,
      previous: { id: previous._id, score: previous.score, createdAt: previous.createdAt },
      current: { id: scan._id, score: scan.score, createdAt: scan.createdAt },
      detail,
    });
  } catch (err) {
    next(err);
  }
}

export async function deleteScan(req, res, next) {
  try {
    const scan = await Scan.findOneAndDelete({ _id: req.params.id, owner: req.userId });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    return res.json({ ok: true });
  } catch (err) {
    next(err);
  }
}

// `sanitizeFileName` is exported from ../utils/validation.js and imported above
// (shared by scanCreate + upload paths so it can be unit-tested directly).

