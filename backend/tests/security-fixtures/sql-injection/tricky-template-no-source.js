// @expects {"case": "tricky", "flagged": true, "verdict": "POTENTIAL", "cwe": "CWE-89"}
// Tricky: a template-literal SQL query with interpolation but no confirmed user
// source. Suspicious shape (report POTENTIAL) rather than a confirmed critical.
const q = `SELECT * FROM users WHERE id=${id}`;
