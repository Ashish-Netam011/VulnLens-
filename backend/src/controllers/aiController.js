/**
 * AI Security Copilot controller (Phase 8).
 *
 * POST /api/ai/explain — turns ONE deterministic finding into a structured
 * security explanation. The deterministic scanner remains the source of
 * truth: this endpoint can never create, suppress, or mutate findings.
 * AI unavailability degrades gracefully (success:false, copilot:null) and
 * never produces an error response for a well-formed request.
 */
import { explainFindingWithAI } from '../ai/copilot.js';

export async function explainFinding(req, res) {
  const { finding, code, fileName } = req.body;
  try {
    // Bounded source context is enforced inside the Copilot service. The
    // finding object is never mutated; provider failures return success:false.
    const result = await explainFindingWithAI(finding, { code, fileName });
    return res.json(result);
  } catch (err) {
    // Last-resort safety net: never leak provider internals, never crash.
    return res.status(500).json({
      success: false,
      copilot: null,
      source: 'error',
      error: 'AI explanation failed',
    });
  }
}