import { Router } from 'express';
import {
  listProjects,
  createProject,
  getProject,
  updateProject,
  deleteProject,
  getProjectOverview,
} from '../controllers/projectController.js';
import { protect } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { projectCreateSchema, projectUpdateSchema } from '../utils/validation.js';

const router = Router();

router.use(protect);

router.get('/', listProjects);
router.post('/', validate(projectCreateSchema), createProject);
router.get('/:id', getProject);
router.get('/:id/overview', getProjectOverview);
router.put('/:id', validate(projectUpdateSchema), updateProject);
router.delete('/:id', deleteProject);

export default router;
