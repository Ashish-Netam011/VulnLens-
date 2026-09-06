// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-89", "ruleId": "sql-concat"}
// Arrow function callback with a SQL sink inside. Before Phase 4D, arrow
// function bodies were never walked — this fixture locks in the fix.
const id = req.query.id;
data.forEach((item) => {
  db.query("SELECT * FROM users WHERE id=" + id);
});