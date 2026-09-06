import { Router } from 'express';
import multer from 'multer';
import {
  listScans,
  createScan,
  getScan,
  getScanComparison,
  deleteScan,
  uploadScan,
} from '../controllers/scanController.js';
import { protect } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { scanCreateSchema } from '../utils/validation.js';
import env from '../config/env.js';

const router = Router();

router.use(protect);

// Multi-file (project folder) upload. Kept in memory; files are validated and
// size-capped in the controller. The per-file / total-file limits keep
// requests bounded while still allowing real source folders.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { files: 100, fileSize: env.MAX_FILE_SIZE_BYTES },
});

router.post('/upload', upload.array('files'), uploadScan);
router.get('/', listScans);
router.post('/', validate(scanCreateSchema), createScan);
router.get('/:id', getScan);
router.get('/:id/comparison', getScanComparison);
router.delete('/:id', deleteScan);

export default router;
