// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-89", "ruleId": "sql-concat"}
// Deferred assignment: the variable is declared without initialization, then
// assigned a user-controlled value before reaching the sink.
let id;
id = req.query.id;
db.query("SELECT * FROM users WHERE id=" + id);