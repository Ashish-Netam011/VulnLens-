// @expects {"case": "safe", "flagged": false, "verdict": "FALSE_POSITIVE", "cwe": null}
// Safe: the JWT signing secret is read from the environment, not hardcoded.
// Regression pin for the Phase 6C literal-only jwtSecret rule fix.
const jwt = require('jsonwebtoken');
const payload = { id: user.id };
jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });