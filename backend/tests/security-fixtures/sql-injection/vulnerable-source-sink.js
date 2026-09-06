// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-89", "ruleId": "sql-assign-concat"}
// Real SQL injection: attacker-controlled req.query.id flows through a local
// variable into a string-concatenated query that reaches db.query().
const id = req.query.id;
const query = "SELECT * FROM users WHERE id=" + id;
db.query(query);
