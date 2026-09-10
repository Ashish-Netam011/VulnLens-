import { Router } from 'express';
import { register, login, me, demo } from '../controllers/authController.js';
import { protect } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { registerSchema, loginSchema } from '../utils/validation.js';
import { createAuthRateLimiter } from '../middleware/rateLimit.js';

const router = Router();
const authLimiter = createAuthRateLimiter();

// Apply stricter rate limit to login/register to slow brute-force attacks.
router.post('/register', authLimiter, validate(registerSchema), register);
router.post('/login', authLimiter, validate(loginSchema), login);
router.get('/me', protect, me);
router.post('/demo', demo);

export default router;
