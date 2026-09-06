import { Router } from 'express';
import { explainFinding } from '../controllers/aiController.js';
import { protect } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { aiExplainSchema } from '../utils/validation.js';

/**
 * Phase 8 — AI Security Copilot endpoint.
 * Auth-protected like every other API route; the request body is bounded by
 * aiExplainSchema (finding fields + optional bounded source context).
 */
const router = Router();

router.use(protect);

router.post('/explain', validate(aiExplainSchema), explainFinding);

export default router;