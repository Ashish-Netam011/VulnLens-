import { generateReport } from '../services/reportService.js';
import { generateSarif, serializeSarif } from '../services/sarifService.js';

export async function getReport(req, res, next) {
  try {
    const report = await generateReport(req.params.id, req.userId);
    return res.json({ report });
  } catch (err) {
    next(err);
  }
}

export async function downloadReport(req, res, next) {
  try {
    const report = await generateReport(req.params.id, req.userId);
    const json = JSON.stringify(report, null, 2);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="vulnlens-report-${req.params.id}.json"`);
    return res.send(json);
  } catch (err) {
    next(err);
  }
}

/**
 * SARIF 2.1.0 report download (Phase 3).
 * Ownership is enforced inside generateSarif exactly like JSON reports, so
 * User A can never download User B's SARIF report. Reuses the centralized
 * error handler for 404 / 403 / malformed-id cases.
 */
export async function downloadSarif(req, res, next) {
  try {
    const sarif = await generateSarif(req.params.id, req.userId);
    const json = serializeSarif(sarif);
    res.setHeader('Content-Type', 'application/sarif+json');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="vulnlens-scan-${req.params.id}.sarif"`
    );
    return res.send(json);
  } catch (err) {
    next(err);
  }
}
