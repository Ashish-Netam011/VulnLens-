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

// Bounded source window for the Finding Detail code viewer / AI Copilot
// context. Read-only, owner-scoped, and resolved PURELY against the scan's own
// stored sources (never the filesystem), so path traversal is impossible by
// construction: the requested file must normalize to an exact stored entry.
const SOURCE_WINDOW_ABOVE = 20; // lines before the target
const SOURCE_WINDOW_BELOW = 19; // lines after the target (≈40 total)
const SOURCE_LINE_MAX_CHARS = 320;

/**
 * Strict source-file parameter grammar. Only a plain, relative, unescaped
 * path is acceptable (e.g. `src/api.js`). Anything that could be a traversal
 * or encoding trick — `..` segments, percent-encoding, backslashes, absolute
 * paths, drive letters, control bytes — is rejected outright with 400 so such
 * attempts can never even be resolved against the stored file list.
 */
function isSafeSourceFileParam(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 500) return false;
  if (value.includes('..')) return false; // traversal segments
  if (value.includes('%')) return false; // encoded traversal/null tricks
  if (value.includes('\\') || value.includes('\0') || value.includes('\r') || value.includes('\n')) return false;
  if (value.startsWith('/') || /^[a-zA-Z]:/.test(value)) return false; // absolute / drive paths
  if (/^[. ]+$/.test(value)) return false;
  return true;
}

export async function getScanSource(req, res, next) {
  try {
    // `around` = target line; must be a positive integer. The client can never
    // request an arbitrary window size.
    const around = Number(req.query.around);
    if (!Number.isInteger(around) || around < 1) {
      return res.status(400).json({ error: 'around must be a positive integer line number' });
    }

    const scan = await Scan.findOne({ _id: req.params.id, owner: req.userId })
      .select('sourceCode fileName sourceFiles.path sourceFiles.content')
      .exec();
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    const sourceFiles = Array.isArray(scan.sourceFiles) ? scan.sourceFiles : [];
    let fileName;
    let content;

    const fileParam = req.query.file;
    const hasFileParam = fileParam !== undefined;
    if (hasFileParam && typeof fileParam === 'string' && !isSafeSourceFileParam(fileParam)) {
      return res.status(400).json({ error: 'Invalid file parameter' });
    }
    // Normalize for comparison against the scan's own stored entries. This is
    // a pure string comparison against stored names — never a filesystem path.
    const requested = typeof fileParam === 'string' ? sanitizeRelativePath(fileParam) : '';

    if (sourceFiles.length > 0) {
      // Multi-file (folder) scan: the file must exactly match a stored entry.
      if (!requested) {
        return res.status(400).json({ error: 'file is required for this scan' });
      }
      const entry = sourceFiles.find((f) => f.path === requested);
      if (!entry) {
        return res.status(404).json({ error: 'Source file not found in this scan' });
      }
      fileName = entry.path;
      content = entry.content || '';
    } else {
      // Single-file scan: one stored source; file param must match it if given.
      if (hasFileParam && requested !== (scan.fileName || '')) {
        return res.status(404).json({ error: 'Source file not found in this scan' });
      }
      fileName = scan.fileName || 'submission.txt';
      content = scan.sourceCode || '';
    }

    const allLines = content.split('\n');
    const total = allLines.length;
    if (around > total) {
      return res.status(400).json({ error: 'Line is out of range for this file' });
    }

    const startLine = Math.max(1, around - SOURCE_WINDOW_ABOVE);
    const endLine = Math.min(total, around + SOURCE_WINDOW_BELOW);
    const lines = [];
    for (let n = startLine; n <= endLine; n++) {
      let code = allLines[n - 1] == null ? '' : allLines[n - 1];
      if (code.length > SOURCE_LINE_MAX_CHARS) code = code.slice(0, SOURCE_LINE_MAX_CHARS - 1) + '…';
      lines.push({ line: n, code });
    }

    return res.json({ success: true, file: fileName, startLine, endLine, targetLine: around, lines });
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

