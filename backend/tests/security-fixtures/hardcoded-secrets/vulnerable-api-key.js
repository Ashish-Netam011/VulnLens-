// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-798", "ruleId": "hardcoded-apiKey"}
// A live-looking API key is embedded literally in source.
const API_KEY = "sk-live-abcdefghijklmnop";
