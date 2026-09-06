// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-89", "ruleId": "sql-concat"}
// Direct inline SQL injection: the user-controlled value is concatenated
// directly into the query at the sink.
db.query("SELECT * FROM users WHERE id=" + req.query.id);
