// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-89", "ruleId": "sql-concat"}
// Destructuring from user-controlled source. Object destructuring was NOT handled
// before Phase 4D — this fixture locks in the fix.
const { id } = req.query;
db.query("SELECT * FROM users WHERE id=" + id);