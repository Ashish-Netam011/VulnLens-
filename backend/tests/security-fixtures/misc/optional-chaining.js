// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-89", "ruleId": "sql-concat"}
// Optional chaining on user input reaching the sink. The ChainExpression
// wrapper must still carry the taint of the underlying MemberExpression.
const id = req.query?.id;
db.query("SELECT * FROM users WHERE id=" + id);