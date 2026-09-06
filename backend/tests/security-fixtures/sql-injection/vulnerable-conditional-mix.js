// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-89", "ruleId": "sql-concat"}
// Conditional (ternary) propagation: one branch is user-controlled, the other
// is safe. The overall expression should be tainted.
const id = req.query.id;
const value = id ? id : "default";
db.query("SELECT * FROM users WHERE id=" + value);