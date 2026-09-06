// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-798", "ruleId": "hardcoded-jwtSecret"}
// Vulnerable: a JWT signing secret is embedded as a literal in the source.
// Regression pin for the Phase 6C literal-only jwtSecret rule fix.
const jwt = require('jsonwebtoken');
const payload = { id: user.id };
jwt.sign(payload, 'hardcoded-jwt-signing-secret-12345', { expiresIn: '7d' });