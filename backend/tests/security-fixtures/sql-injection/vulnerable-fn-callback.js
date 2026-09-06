// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-89", "ruleId": "sql-concat"}
// Function expression callback with a SQL sink inside. Before Phase 4D,
// function expression bodies were never walked — this locks in the fix.
const id = req.query.id;
data.forEach(function (item) {
  db.query("SELECT * FROM users WHERE id=" + id);
});