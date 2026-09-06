import { Router } from 'express';
import { getReport, downloadReport, downloadSarif } from '../controllers/reportController.js';
import { protect } from '../middleware/auth.js';

const router = Router();

router.use(protect);

router.get('/:id', getReport);
router.get('/:id/download', downloadReport);
router.get('/:id/sarif', downloadSarif);

export default router;
