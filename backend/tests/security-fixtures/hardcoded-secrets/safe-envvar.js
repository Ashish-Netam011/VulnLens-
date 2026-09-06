// @expects {"case": "safe", "flagged": false, "verdict": "FALSE_POSITIVE", "cwe": null}
// Safe: the secret is read from the environment, not hardcoded.
const API_KEY = process.env.API_KEY;
