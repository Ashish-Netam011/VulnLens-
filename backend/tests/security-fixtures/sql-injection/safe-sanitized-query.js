// @expects {"case": "safe", "flagged": true, "verdict": "POTENTIAL", "cwe": "CWE-89"}
// The user-controlled value is passed through a recognized sanitizer
// (encodeURIComponent) before reaching the query sink, so it cannot be
// confirmed as exploitable. Reported as a low-severity POTENTIAL lead only.
const id = req.query.id;
db.query("SELECT * FROM users WHERE id=" + encodeURIComponent(id));