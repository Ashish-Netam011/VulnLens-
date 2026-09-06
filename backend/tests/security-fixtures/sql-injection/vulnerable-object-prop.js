// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-89", "ruleId": "sql-concat"}
// Object property propagation: the user-controlled value is placed inside an
// object literal, then accessed via property access at the sink.
const input = { id: req.query.id };
db.query("SELECT * FROM users WHERE id=" + input.id);