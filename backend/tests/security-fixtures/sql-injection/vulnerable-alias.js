// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-89", "ruleId": "sql-concat"}
// Taint propagation through an alias variable. The user-controlled value is
// copied to a second variable before reaching the query sink.
const id = req.query.id;
const value = id;
db.query("SELECT * FROM users WHERE id=" + value);