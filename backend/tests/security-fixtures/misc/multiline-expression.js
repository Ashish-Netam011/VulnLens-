// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-89", "ruleId": "sql-concat"}
// Multiline expression: the user-controlled source spans multiple physical
// lines before reaching the query sink via concatenation.
const id =
  req.query.id;
db.query("SELECT * FROM users WHERE id=" + id);